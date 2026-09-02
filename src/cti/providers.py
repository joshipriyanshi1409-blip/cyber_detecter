"""
Threat Intelligence Provider Interface
Abstract base class and implementations for CTI providers.
"""

import logging
import time
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
import requests
import os

logger = logging.getLogger(__name__)


@dataclass
class CTIResult:
    """Standardized threat intelligence result"""
    indicator: str
    indicator_type: str  # 'ip', 'domain', 'url', 'hash'
    is_malicious: bool
    confidence: float
    source: str
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


class ThreatIntelligenceProvider(ABC):
    """Abstract base class for threat intelligence providers"""
    
    def __init__(self, name: str, api_key: Optional[str] = None):
        """
        Initialize provider
        
        Args:
            name: Provider name
            api_key: API key for authentication
        """
        self.name = name
        self.api_key = api_key
        self.timeout = 5  # Default timeout in seconds
        self.enabled = True
        
        logger.info(f"Initialized {name} provider")
    
    @abstractmethod
    def lookup_ip(self, ip: str) -> Optional[CTIResult]:
        """Look up IP address"""
        pass
    
    @abstractmethod
    def lookup_domain(self, domain: str) -> Optional[CTIResult]:
        """Look up domain name"""
        pass
    
    def lookup(self, indicator: str) -> Optional[CTIResult]:
        """Generic lookup based on indicator type"""
        if self._is_ip(indicator):
            return self.lookup_ip(indicator)
        elif self._is_domain(indicator):
            return self.lookup_domain(indicator)
        else:
            return None
    
    def _is_ip(self, value: str) -> bool:
        """Check if value is an IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    def _is_domain(self, value: str) -> bool:
        """Check if value is a domain name"""
        import re
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$'
        return bool(re.match(domain_pattern, value))
    
    def _make_request(self, url: str, headers: Optional[Dict] = None) -> Optional[Dict]:
        """Make HTTP request with error handling"""
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"{self.name}: HTTP {response.status_code}")
                return None
        except requests.exceptions.Timeout:
            logger.warning(f"{self.name}: Request timeout")
            return None
        except requests.exceptions.ConnectionError:
            logger.warning(f"{self.name}: Connection error")
            return None
        except Exception as e:
            logger.warning(f"{self.name}: Request failed: {e}")
            return None
    
    def is_available(self) -> bool:
        """Check if provider is available"""
        return self.enabled and (self.api_key is not None or not self._requires_api_key())
    
    def _requires_api_key(self) -> bool:
        """Check if provider requires API key"""
        return False


class ThreatFoxProvider(ThreatIntelligenceProvider):
    """ThreatFox threat intelligence provider"""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__("ThreatFox", api_key)
        self.base_url = "https://threatfox-api.abuse.ch/api/v1/"
    
    def _requires_api_key(self) -> bool:
        return False  # ThreatFox has free API without key
    
    def lookup_ip(self, ip: str) -> Optional[CTIResult]:
        """Look up IP in ThreatFox"""
        data = {
            "query": "search_ioc",
            "search_term": ip
        }
        
        try:
            response = requests.post(self.base_url, json=data, timeout=self.timeout)
            if response.status_code == 200:
                result = response.json()
                
                if result.get("query_status") == "ok":
                    is_malicious = len(result.get("data", [])) > 0
                    return CTIResult(
                        indicator=ip,
                        indicator_type="ip",
                        is_malicious=is_malicious,
                        confidence=0.8 if is_malicious else 0.1,
                        source=self.name,
                        details={
                            "matches": len(result.get("data", [])),
                            "raw_data": result.get("data", [])[:5]
                        }
                    )
        except Exception as e:
            logger.warning(f"ThreatFox lookup failed: {e}")
        
        return None
    
    def lookup_domain(self, domain: str) -> Optional[CTIResult]:
        """Look up domain in ThreatFox"""
        data = {
            "query": "search_ioc",
            "search_term": domain
        }
        
        try:
            response = requests.post(self.base_url, json=data, timeout=self.timeout)
            if response.status_code == 200:
                result = response.json()
                
                if result.get("query_status") == "ok":
                    is_malicious = len(result.get("data", [])) > 0
                    return CTIResult(
                        indicator=domain,
                        indicator_type="domain",
                        is_malicious=is_malicious,
                        confidence=0.8 if is_malicious else 0.1,
                        source=self.name,
                        details={
                            "matches": len(result.get("data", [])),
                            "raw_data": result.get("data", [])[:5]
                        }
                    )
        except Exception as e:
            logger.warning(f"ThreatFox lookup failed: {e}")
        
        return None


class URLhausProvider(ThreatIntelligenceProvider):
    """URLhaus threat intelligence provider"""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__("URLhaus", api_key)
        self.base_url = "https://urlhaus-api.abuse.ch/v1/"
    
    def lookup_ip(self, ip: str) -> Optional[CTIResult]:
        """Look up IP in URLhaus"""
        return self._make_request(f"{self.base_url}host/")
    
    def lookup_domain(self, domain: str) -> Optional[CTIResult]:
        """Look up domain in URLhaus"""
        data = {
            "host": domain
        }
        
        try:
            response = requests.post(f"{self.base_url}host/", data=data, timeout=self.timeout)
            if response.status_code == 200:
                result = response.json()
                
                if result.get("query_status") == "ok":
                    is_malicious = len(result.get("urls", [])) > 0
                    return CTIResult(
                        indicator=domain,
                        indicator_type="domain",
                        is_malicious=is_malicious,
                        confidence=0.7 if is_malicious else 0.1,
                        source=self.name,
                        details={
                            "url_count": len(result.get("urls", [])),
                            "raw_data": result.get("urls", [])[:5]
                        }
                    )
        except Exception as e:
            logger.warning(f"URLhaus lookup failed: {e}")
        
        return None


class LocalThreatIntelligenceProvider(ThreatIntelligenceProvider):
    """Local threat intelligence provider (offline, from file)"""
    
    def __init__(self, data_file: Optional[str] = None):
        super().__init__("LocalCTI", None)
        self.data_file = data_file
        self.malicious_ips = set()
        self.malicious_domains = set()
        self._load_data()
    
    def _load_data(self):
        """Load malicious indicators from file"""
        if not self.data_file:
            # Use default demo data
            self.malicious_ips = {
                "10.0.0.1", "10.0.0.2", "192.168.1.200",
                "185.220.101.1", "185.220.102.2"
            }
            self.malicious_domains = {
                "malware.example.com", "phishing.example.net",
                "x8j2k9lqpz12345.com", "m4n7b2vxwq98765.net"
            }
            return
        
        try:
            import json
            with open(self.data_file, 'r') as f:
                data = json.load(f)
                self.malicious_ips = set(data.get('malicious_ips', []))
                self.malicious_domains = set(data.get('malicious_domains', []))
            logger.info(f"Loaded {len(self.malicious_ips)} IPs and {len(self.malicious_domains)} domains")
        except Exception as e:
            logger.warning(f"Failed to load CTI data: {e}")
    
    def lookup_ip(self, ip: str) -> Optional[CTIResult]:
        """Look up IP in local data"""
        is_malicious = ip in self.malicious_ips
        return CTIResult(
            indicator=ip,
            indicator_type="ip",
            is_malicious=is_malicious,
            confidence=0.9 if is_malicious else 0.05,
            source=self.name,
            details={
                "in_local_database": True,
                "database_size": len(self.malicious_ips)
            }
        )
    
    def lookup_domain(self, domain: str) -> Optional[CTIResult]:
        """Look up domain in local data"""
        is_malicious = domain.lower() in self.malicious_domains
        return CTIResult(
            indicator=domain,
            indicator_type="domain",
            is_malicious=is_malicious,
            confidence=0.9 if is_malicious else 0.05,
            source=self.name,
            details={
                "in_local_database": True,
                "database_size": len(self.malicious_domains)
            }
        )
    