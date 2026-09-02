"""
DGA (Domain Generation Algorithm) Detection Module
Detects suspicious domain names using entropy and structure analysis.
"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
import time
import re

from src.flow.nfstream_wrapper import FlowRecord
from src.features.entropy import DomainEntropyAnalyzer, EntropyCalculator

try:
    from src.utils.config import config_manager
except ImportError:
    from src.utils.config_simple import config_manager

logger = logging.getLogger(__name__)


@dataclass
class DGAResult:
    """Standardized DGA detection result"""
    threat_type: str = "DGA_SUSPICIOUS_DOMAIN"
    source_ip: str = ""
    destination_ip: str = ""
    domain: str = ""
    confidence: float = 0.0
    severity: str = "MEDIUM"
    risk_score: float = 0.0
    detector: str = "rule_based_dga"
    details: Dict[str, Any] = None
    timestamp: float = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()
        if self.details is None:
            self.details = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


class DGADetector:
    """Detects DGA-generated domain names"""
    
    def __init__(self):
        """Initialize DGA detector"""
        self.thresholds = self._load_thresholds()
        self.domain_analyzer = DomainEntropyAnalyzer()
        self.domain_history = defaultdict(list)
        
        # Common legitimate domains whitelist
        self.whitelist = {
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'netflix.com', 'twitter.com', 'instagram.com',
            'linkedin.com', 'github.com', 'youtube.com', 'wikipedia.org',
            'yahoo.com', 'reddit.com', 'ebay.com', 'paypal.com',
            'office.com', 'adobe.com', 'dropbox.com', 'spotify.com'
        }
        
        logger.info(f"Initialized DGADetector with thresholds: {self.thresholds}")
    
    def _load_thresholds(self) -> Dict[str, Any]:
        """Load detection thresholds from config"""
        defaults = {
            "min_domain_length": 12,  # Increased to avoid false positives
            "max_domain_length": 64,
            "entropy_threshold": 3.0,  # Requires high entropy
            "digit_ratio_threshold": 0.1,  # Requires some digits
            "ngram_score_threshold": 0.05,
            "nxdomain_rate_threshold": 0.3,
            "min_queries": 3
        }
        
        try:
            thresholds = {
                "min_domain_length": config_manager.get_threshold(
                    "dga", "min_length", default=defaults["min_domain_length"]
                ),
                "max_domain_length": config_manager.get_threshold(
                    "dga", "max_length", default=defaults["max_domain_length"]
                ),
                "entropy_threshold": config_manager.get_threshold(
                    "dga", "min_entropy", default=defaults["entropy_threshold"]
                ),
                "digit_ratio_threshold": config_manager.get_threshold(
                    "dga", "digit_ratio_threshold",
                    default=config_manager.get_threshold(
                        "dga", "max_digit_ratio", default=defaults["digit_ratio_threshold"]
                    ),
                ),
                "ngram_score_threshold": config_manager.get_threshold(
                    "dga", "ngram_score", default=defaults["ngram_score_threshold"]
                ),
                "nxdomain_rate_threshold": config_manager.get_threshold(
                    "dga", "nxdomain_rate_threshold", default=defaults["nxdomain_rate_threshold"]
                ),
                "min_queries": config_manager.get_threshold(
                    "dga", "min_queries", default=defaults["min_queries"]
                )
            }
            return thresholds
        except Exception as e:
            logger.warning(f"Failed to load thresholds: {e}. Using defaults.")
            return defaults
    
    def detect(self, flows: List[FlowRecord]) -> List[DGAResult]:
        """Detect DGA-like domains from flows"""
        if not flows:
            return []
        
        detections = []
        dns_queries = self._extract_dns_queries(flows)
        
        queries_by_source = defaultdict(list)
        for query in dns_queries:
            queries_by_source[query["source_ip"]].append(query)
        
        for source_ip, queries in queries_by_source.items():
            suspicious_domains = self._analyze_source_domains(source_ip, queries)
            detections.extend(suspicious_domains)
        
        logger.info(f"DGADetector: Detected {len(detections)} suspicious domains")
        return detections
    
    def _extract_dns_queries(self, flows: List[FlowRecord]) -> List[Dict[str, Any]]:
        """Extract DNS queries from flows"""
        queries = []
        
        for flow in flows:
            if flow.destination_port == 53 or flow.source_port == 53:
                domain = getattr(flow, 'dns_query', '')
                
                queries.append({
                    "source_ip": flow.source_ip,
                    "destination_ip": flow.destination_ip,
                    "domain": domain,
                    "timestamp": flow.timestamp,
                    "is_nxdomain": self._check_nxdomain(flow)
                })
        
        return queries
    
    def _check_nxdomain(self, flow: FlowRecord) -> bool:
        """Return the explicit DNS NXDOMAIN state; missing stays False for legacy bool API."""
        return bool(flow.dns_nxdomain) if flow.dns_nxdomain is not None else False
    
    def analyze_domain(self, domain: str, source_ip: str = "", nxdomain_rate: Optional[float] = None) -> Optional[DGAResult]:
        """
        Analyze a single domain for DGA characteristics
        
        Args:
            domain: Domain name to analyze
            source_ip: Source IP that queried this domain
            
        Returns:
            DGAResult if suspicious, None otherwise
        """
        if not domain:
            return None
        
        # Clean domain
        clean_domain = domain.lower().strip()
        if '://' in clean_domain:
            clean_domain = clean_domain.split('://')[1]
        if '/' in clean_domain:
            clean_domain = clean_domain.split('/')[0]
        if ':' in clean_domain:
            clean_domain = clean_domain.split(':')[0]
        
        # Check whitelist first
        if clean_domain in self.whitelist:
            return None
        
        # Get domain features
        features = self.domain_analyzer.analyze_domain(clean_domain)
        
        # DGA indicators - require MULTIPLE indicators
        indicators = []
        evidence = {}
        
        # Check domain length (DGA domains are typically long)
        if features["length"] >= self.thresholds["min_domain_length"]:
            indicators.append("length")
            evidence["length"] = features["length"]
        
        # Check entropy (DGA domains have high entropy)
        if features["entropy"] >= self.thresholds["entropy_threshold"]:
            indicators.append("entropy")
            evidence["entropy"] = features["entropy"]
        
        # Check digit ratio (DGA domains often contain digits)
        if features["digit_ratio"] >= self.thresholds["digit_ratio_threshold"]:
            indicators.append("digit_ratio")
            evidence["digit_ratio"] = features["digit_ratio"]
        
        # Check n-gram score (DGA domains have low n-gram scores)
        ngram_score = features.get("ngram_score", 1.0)
        if ngram_score <= self.thresholds["ngram_score_threshold"]:
            indicators.append("ngram_score")
            evidence["ngram_score"] = ngram_score
        
        if nxdomain_rate is not None:
            evidence["nxdomain_rate"] = nxdomain_rate
            if nxdomain_rate >= self.thresholds["nxdomain_rate_threshold"]:
                indicators.append("nxdomain_rate")

        # Require at least 2 independent indicators for detection.
        if len(indicators) < 2:
            return None
        
        # Calculate confidence based on number and strength of indicators
        confidence = min(0.3 + (len(indicators) * 0.15), 1.0)
        
        # Boost confidence for strong indicators
        if "entropy" in indicators and features["entropy"] > 3.5:
            confidence += 0.1
        if "digit_ratio" in indicators and features["digit_ratio"] > 0.15:
            confidence += 0.1
        
        confidence = min(confidence, 1.0)
        
        # Determine severity
        severity = self._determine_severity(features, len(indicators), confidence)
        
        return DGAResult(
            source_ip=source_ip,
            destination_ip="",
            domain=clean_domain,
            confidence=confidence,
            severity=severity,
            risk_score=confidence * 100,
            details={
                "features": features,
                "evidence": evidence,
                "indicators": indicators,
                "thresholds": self.thresholds
            }
        )
    
    def _analyze_source_domains(self, source_ip: str, queries: List[Dict[str, Any]]) -> List[DGAResult]:
        """Analyze domains plus source-level NXDOMAIN/query-history evidence."""
        self.domain_history[source_ip].extend(queries)
        # Bound per-source and global history to prevent attacker-controlled
        # source churn from turning DGA tracking into an unbounded cache.
        self.domain_history[source_ip] = self.domain_history[source_ip][-10000:]
        total_history = sum(len(items) for items in self.domain_history.values())
        while total_history > 100000 and self.domain_history:
            oldest_source = next(iter(self.domain_history))
            self.domain_history.pop(oldest_source, None)
            total_history = sum(len(items) for items in self.domain_history.values())

        query_count = len(queries)
        nxdomain_count = sum(1 for q in queries if q.get("is_nxdomain"))
        nxdomain_rate = nxdomain_count / query_count if query_count else None

        results = []
        for query in queries:
            domain = query.get("domain", "")
            if not domain:
                continue
            result = self.analyze_domain(
                domain,
                source_ip,
                nxdomain_rate=nxdomain_rate if query_count >= self.thresholds["min_queries"] else None,
            )
            if result:
                result.destination_ip = query.get("destination_ip", "")
                if query.get("timestamp") is not None:
                    result.timestamp = query["timestamp"]
                result.details["query_count"] = query_count
                result.details["nxdomain_count"] = nxdomain_count
                result.details["nxdomain_rate"] = nxdomain_rate
                result.details["thresholds"]["min_queries"] = self.thresholds["min_queries"]
                results.append(result)

        if query_count >= self.thresholds["min_queries"] and results:
            for result in results:
                result.confidence = min(result.confidence * 1.2, 1.0)
                result.risk_score = result.confidence * 100
        return results

    def detect_from_domains(self, domains: List[str], source_ip: str = "") -> List[DGAResult]:
        """Analyze a list of domains for DGA characteristics"""
        results = []
        
        for domain in domains:
            result = self.analyze_domain(domain, source_ip)
            if result:
                results.append(result)
        
        return results
    
    def _determine_severity(self, features: Dict[str, Any], num_indicators: int, confidence: float) -> str:
        """Determine DGA severity based on features"""
        if num_indicators >= 3 and confidence > 0.7:
            return "HIGH"
        elif num_indicators >= 2 and confidence > 0.5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_domain_statistics(self, domains: List[str]) -> Dict[str, Any]:
        """Get statistics about domain characteristics"""
        stats = {
            "total_domains": len(domains),
            "average_entropy": 0,
            "average_length": 0,
            "average_digit_ratio": 0,
            "suspicious_count": 0,
            "high_entropy_count": 0,
            "long_domain_count": 0
        }
        
        if not domains:
            return stats
        
        entropies = []
        lengths = []
        digit_ratios = []
        
        for domain in domains:
            features = self.domain_analyzer.analyze_domain(domain)
            entropies.append(features["entropy"])
            lengths.append(features["length"])
            digit_ratios.append(features["digit_ratio"])
            
            if features["entropy"] >= self.thresholds["entropy_threshold"]:
                stats["high_entropy_count"] += 1
            
            if features["length"] >= self.thresholds["min_domain_length"]:
                stats["long_domain_count"] += 1
        
        stats["average_entropy"] = sum(entropies) / len(entropies)
        stats["average_length"] = sum(lengths) / len(lengths)
        stats["average_digit_ratio"] = sum(digit_ratios) / len(digit_ratios)
        stats["suspicious_count"] = len(self.detect_from_domains(domains))
        
        return stats