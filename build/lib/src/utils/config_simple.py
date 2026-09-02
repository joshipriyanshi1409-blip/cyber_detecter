"""
Simple configuration module (fallback)
Provides default thresholds without complex YAML loading.
"""

# Default detection thresholds
DEFAULT_THRESHOLDS = {
    "port_scan": {
        "min_unique_ports": 10,
        "min_unique_hosts": 5,
        "min_failed_ratio": 0.5,
        "min_syn_ratio": 0.7,
        "window_seconds": 60,
        "min_flows": 5
    },
    "ddos": {
        "min_pps": 1000,
        "min_bps": 100000,
        "min_syn_ratio": 0.7,
        "source_concentration": 0.5,
        "window_seconds": 10,
        "min_flows": 10
    },
    "syn_flood": {
        "min_flows": 5,
        "min_syn_only_pps": 100.0,
        "max_ack_completion_ratio": 0.3,
        "destination_concentration_threshold": 0.5,
        "min_spoofing_likelihood": 0.4
    },
    "udp_flood": {
        "min_flows": 5,
        "min_udp_pps": 500.0,
        "dest_port_concentration_threshold": 0.5,
        "destination_concentration_threshold": 0.5,
        "min_one_packet_source_ratio": 0.5,
        "reflection_min_amplification_ratio": 5.0,
        "reflection_min_flows": 5,
        "reflection_min_reply_bytes": 5000
    },
    "cti": {
        # Section 27: rate-limit CTI lookups. Cache hits don't count
        # against this budget -- see src/cti/rate_limiter.py.
        "max_lookups_per_window": 60,
        "rate_limit_window_seconds": 60.0
    },
    "dga": {
        "min_length": 8,
        "max_length": 64,
        "min_entropy": 3.5,
        "max_digit_ratio": 0.3,
        "ngram_score": 0.1,
        "min_queries": 3
    },
    "risk_scoring": {
        "low": 30,
        "medium": 60,
        "high": 80,
        "critical": 100
    }
}


def get_threshold(detector: str, param: str, default=None):
    """Get threshold value with fallback"""
    return DEFAULT_THRESHOLDS.get(detector, {}).get(param, default)


# Create a simple config_manager object for compatibility
class SimpleConfigManager:
    def __init__(self):
        self.configs = {
            'main': {},
            'thresholds': DEFAULT_THRESHOLDS
        }
    
    def get_threshold(self, detector, param, default=None):
        return get_threshold(detector, param, default)
    
    def get(self, config_name, *keys, default=None):
        if config_name == 'thresholds' and keys:
            current = DEFAULT_THRESHOLDS
            for key in keys:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return default
            return current
        return default


config_manager = SimpleConfigManager()