"""
Threat Intelligence Enrichment Module
Enriches alerts with threat intelligence data.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import os

from src.cti.providers import ThreatIntelligenceProvider, CTIResult, LocalThreatIntelligenceProvider, ThreatFoxProvider
from src.cti.rate_limiter import CTIRateLimiter
from src.alerts.alert_models import Alert

logger = logging.getLogger(__name__)


class ThreatIntelligenceEnricher:
    """Enriches alerts with threat intelligence data"""
    
    def __init__(self, providers: Optional[List[ThreatIntelligenceProvider]] = None,
                 max_lookups_per_window: int = 60, rate_limit_window_seconds: float = 60.0):
        """
        Initialize enricher
        
        Args:
            providers: List of CTI providers (defaults to local provider)
            max_lookups_per_window: cap on external lookups per rolling window
                (Section 27: "Rate-limit CTI lookups ... prevent attacker-controlled
                traffic from creating unlimited external lookups.")
            rate_limit_window_seconds: width of the rolling rate-limit window
        """
        if providers is None:
            # Default to local provider only
            providers = [LocalThreatIntelligenceProvider()]
        
        self.providers = providers
        self.enabled = len(providers) > 0
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour cache
        self.rate_limiter = CTIRateLimiter(
            max_requests=max_lookups_per_window,
            window_seconds=rate_limit_window_seconds,
        )
        
        logger.info(f"Initialized ThreatIntelligenceEnricher with {len(providers)} providers")
    
    def enrich_alert(self, alert: Alert) -> Alert:
        """
        Enrich alert with threat intelligence
        
        Args:
            alert: Alert to enrich
            
        Returns:
            Enriched alert
        """
        if not self.enabled:
            return alert
        
        rate_limited_indicators = []
        statuses=[]

        # Enrich source IP
        if alert.source_ip:
            source_result, source_status = self.lookup_indicator_with_status(alert.source_ip, "ip")
            statuses.append(source_status)
            if source_status == "rate_limited":
                rate_limited_indicators.append(f"ip:{alert.source_ip}")
            if source_result and source_result.is_malicious:
                alert.details['cti_source_ip'] = source_result.to_dict()
                alert.details['cti_source_malicious'] = True
                
                # Boost risk score
                alert.details['cti_risk_contribution'] = alert.details.get('cti_risk_contribution', 0.0) + 10.0
                alert.cti_score = alert.details['cti_risk_contribution']
        
        # Enrich destination IP
        if alert.destination_ip:
            dest_result, dest_status = self.lookup_indicator_with_status(alert.destination_ip, "ip")
            statuses.append(dest_status)
            if dest_status == "rate_limited":
                rate_limited_indicators.append(f"ip:{alert.destination_ip}")
            if dest_result and dest_result.is_malicious:
                alert.details['cti_destination_ip'] = dest_result.to_dict()
                alert.details['cti_destination_malicious'] = True
                
                # Boost risk score
                alert.details['cti_risk_contribution'] = alert.details.get('cti_risk_contribution', 0.0) + 5.0
                alert.cti_score = alert.details['cti_risk_contribution']
        
        # Enrich domain if present
        domain = alert.details.get('domain')
        if domain:
            domain_result, domain_status = self.lookup_indicator_with_status(domain, "domain")
            statuses.append(domain_status)
            if domain_status == "rate_limited":
                rate_limited_indicators.append(f"domain:{domain}")
            if domain_result and domain_result.is_malicious:
                alert.details['cti_domain'] = domain_result.to_dict()
                alert.details['cti_domain_malicious'] = True
                
                # Boost risk score
                alert.details['cti_risk_contribution'] = alert.details.get('cti_risk_contribution', 0.0) + 15.0
                alert.cti_score = alert.details['cti_risk_contribution']
        
        # Section 35: a degraded/rate-limited CTI check must never read
        # the same as "checked, nothing found". Record it explicitly on
        # the alert so downstream consumers (dashboard, DB) can see that
        # some indicators were not actually checked this pass.
        if rate_limited_indicators:
            alert.details['cti_rate_limited'] = True
            alert.details['cti_rate_limited_indicators'] = rate_limited_indicators
        if "rate_limited" in statuses:
            alert.cti_status = "PARTIAL"
        elif "unavailable" in statuses:
            alert.cti_status = "UNAVAILABLE"
        elif statuses:
            alert.cti_status = "CACHE_HIT" if all(x=="cache_hit" for x in statuses) else "CHECKED"
        else:
            alert.cti_status = "DISABLED"

        return alert
    
    def lookup_indicator(self, indicator: str, indicator_type: str = "") -> Optional[CTIResult]:
        """
        Look up indicator across all providers. Convenience wrapper around
        lookup_indicator_with_status() for callers that don't need to
        distinguish "checked, not malicious" from "skipped, rate-limited".
        """
        result, _status = self.lookup_indicator_with_status(indicator, indicator_type)
        return result

    def lookup_indicator_with_status(self, indicator: str, indicator_type: str = "") -> "tuple[Optional[CTIResult], str]":
        """
        Look up indicator across all providers.

        Args:
            indicator: IP, domain, or URL to look up
            indicator_type: Type of indicator

        Returns:
            (Aggregated CTIResult or None, status) where status is one of:
              "cache_hit"     - served from cache, no external call made
              "checked"       - providers were actually queried
              "rate_limited"  - external lookup skipped; NOT the same as a
                                 negative result, and never cached as one
                                 (Section 35: a degraded subsystem must
                                 never read as "no threat")
        """
        # Check cache first -- a cache hit never counts against the rate
        # limit, since it makes no external call.
        cache_key = f"{indicator_type}:{indicator}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if cached['timestamp'] + self.cache_ttl > __import__('time').time():
                return cached['result'], "cache_hit"

        if not self.rate_limiter.allow():
            logger.warning(
                f"CTI rate limit exceeded ({self.rate_limiter.max_requests}/"
                f"{self.rate_limiter.window_seconds}s); skipping external lookup "
                f"for {indicator_type}:{indicator} (not cached as negative)"
            )
            return None, "rate_limited"

        results = []
        
        for provider in self.providers:
            try:
                if not provider.is_available():
                    continue
                available_provider = True
                
                result = provider.lookup(indicator)
                if result:
                    results.append(result)
            except Exception as e:
                logger.warning(f"Provider {provider.name} failed: {e}")
        
        if not results and not available_provider:
            return None, "unavailable"
        if not results:
            # Cache negative result -- safe here because this is a genuine
            # "checked, nothing flagged" outcome, not a skipped lookup.
            self.cache[cache_key] = {
                'result': None,
                'timestamp': __import__('time').time()
            }
            return None, "checked"
        
        # Aggregate results
        aggregated = self._aggregate_results(results)
        
        # Cache result
        self.cache[cache_key] = {
            'result': aggregated,
            'timestamp': __import__('time').time()
        }
        
        return aggregated, "checked"
    
    def _aggregate_results(self, results: List[CTIResult]) -> CTIResult:
        """Aggregate multiple CTI results"""
        if not results:
            return None
        
        # Check if any provider flags as malicious
        is_malicious = any(r.is_malicious for r in results)
        
        # Calculate average confidence
        avg_confidence = sum(r.confidence for r in results) / len(results)
        
        # Use first result as base
        base = results[0]
        
        return CTIResult(
            indicator=base.indicator,
            indicator_type=base.indicator_type,
            is_malicious=is_malicious,
            confidence=avg_confidence,
            source="+".join(r.source for r in results),
            details={
                'providers_checked': len(results),
                'providers_flagged': sum(1 for r in results if r.is_malicious),
                'individual_results': [r.to_dict() for r in results]
            }
        )
    
    def _get_severity(self, risk_score: float) -> str:
        """Map risk score to severity"""
        if risk_score >= 81:
            return "CRITICAL"
        elif risk_score >= 61:
            return "HIGH"
        elif risk_score >= 31:
            return "MEDIUM"
        else:
            return "LOW"
    
    def batch_enrich(self, alerts: List[Alert]) -> List[Alert]:
        """Enrich multiple alerts"""
        enriched = []
        for alert in alerts:
            try:
                enriched_alert = self.enrich_alert(alert)
                enriched.append(enriched_alert)
            except Exception as e:
                logger.error(f"Failed to enrich alert {alert.alert_id}: {e}")
                enriched.append(alert)  # Keep original
        
        logger.info(f"Enriched {len(enriched)} alerts")
        return enriched
    
    def get_provider_status(self) -> Dict[str, Any]:
        """Get status of all providers, plus CTI rate-limiter health (Section 35)."""
        status = {}
        for provider in self.providers:
            status[provider.name] = {
                'enabled': provider.enabled,
                'available': provider.is_available(),
                'requires_api_key': provider._requires_api_key()
            }
        status['_rate_limiter'] = self.rate_limiter.get_status()
        return status
    
    def clear_cache(self):
        """Clear lookup cache"""
        self.cache.clear()
        logger.info("Cleared CTI cache")