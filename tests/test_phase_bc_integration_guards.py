from datetime import datetime, timezone
from src.risk.authoritative_risk import Evidence, calculate_risk

def test_authoritative_breakdown_reproduces_score():
    ev = [
        Evidence("rule","syn","syn_ratio",0.9,0.8,40,"high SYN-only ratio",datetime.now(timezone.utc)),
        Evidence("cti","cti","malicious_ip",True,None,15,"malicious source",datetime.now(timezone.utc)),
    ]
    result = calculate_risk(ev)
    assert result.score == 55
    assert sum(x["contribution"] for x in result.breakdown) == result.score
