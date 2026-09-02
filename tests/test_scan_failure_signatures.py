"""
Tests for src.detectors.scan -- SYN-only vs RST-refused failure signatures.

Covers audit item 7 (see docs/AUDIT_PROGRESS.md #7 and
docs/NEXT_AGENT_PROMPT.md item 7): the original code had

    if flow.syn_packets > 0 and flow.ack_packets == 0:
        syn_only_count += 1
        failed_connections += 1
    elif flow.syn_packets > 0 and flow.ack_packets == 0:
        failed_connections += 1

The `elif` had the IDENTICAL condition as the `if`, so it was unreachable
dead code -- `rst_packets` was never consulted anywhere in the module. The
fix distinguishes two real failure signatures:
    1. SYN sent, no ACK, no RST  -> no response at all (syn_only_count).
    2. SYN sent, RST received    -> actively refused (failed_connections
       only, NOT counted as syn_only).

This test is dependency-free: it imports src.detectors.scan and
src.flow.nfstream_wrapper directly (both import cleanly without
nfstream/scapy/pytest -- verified separately), and runs standalone with
`python3 tests/test_scan_failure_signatures.py`.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.detectors.scan import PortScanDetector
from src.flow.nfstream_wrapper import FlowRecord


def make_flow(dest_port, syn_packets=1, ack_packets=0, rst_packets=0, protocol=6):
    """Minimal-but-complete FlowRecord for a single TCP attempt."""
    now_ms = int(time.time() * 1000)
    return FlowRecord(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        source_port=40000 + dest_port,
        destination_port=dest_port,
        protocol=protocol,
        bidirectional_packets=syn_packets + ack_packets + rst_packets,
        bidirectional_bytes=(syn_packets + ack_packets + rst_packets) * 60,
        bidirectional_duration_ms=5,
        src2dst_packets=syn_packets,
        src2dst_bytes=syn_packets * 60,
        dst2src_packets=ack_packets + rst_packets,
        dst2src_bytes=(ack_packets + rst_packets) * 60,
        bidirectional_first_seen_ms=now_ms,
        bidirectional_last_seen_ms=now_ms + 5,
        bidirectional_min_ps=60,
        bidirectional_mean_ps=60,
        bidirectional_stddev_ps=0,
        bidirectional_max_ps=60,
        bidirectional_min_piat_ms=0,
        bidirectional_mean_piat_ms=1,
        bidirectional_stddev_piat_ms=0,
        bidirectional_max_piat_ms=1,
        syn_packets=syn_packets,
        ack_packets=ack_packets,
        fin_packets=0,
        rst_packets=rst_packets,
    )


def test_syn_only_no_response_counts_as_syn_only():
    """SYN sent, nothing back at all -> syn_only_count, not RST-refused."""
    detector = PortScanDetector()
    flows = [make_flow(dest_port=p, syn_packets=1, ack_packets=0, rst_packets=0)
              for p in range(1, 21)]
    result = detector._analyze_source_flows("10.0.0.1", flows)
    assert result is not None, "expected a scan result for 20 unresponsive SYNs"
    assert result.details["syn_only_count"] == 20, result.details["syn_only_count"]
    assert result.details["failed_connections"] == 20, result.details["failed_connections"]
    print("PASS: silent/no-response SYNs counted as syn_only")


def test_rst_refused_counts_as_failed_but_not_syn_only():
    """SYN sent, RST received -> failed_connections only, NOT syn_only."""
    detector = PortScanDetector()
    flows = [make_flow(dest_port=p, syn_packets=1, ack_packets=0, rst_packets=1)
              for p in range(1, 21)]
    result = detector._analyze_source_flows("10.0.0.1", flows)
    assert result is not None, "expected a scan result for 20 RST-refused SYNs"
    assert result.details["syn_only_count"] == 0, (
        f"RST-refused connections must NOT be counted as syn_only, got "
        f"{result.details['syn_only_count']}"
    )
    assert result.details["failed_connections"] == 20, result.details["failed_connections"]
    print("PASS: RST-refused SYNs counted as failed but not syn_only")


def test_mixed_signatures_split_correctly():
    """A mix of silent-drop and RST-refused ports is split correctly."""
    detector = PortScanDetector()
    silent = [make_flow(dest_port=p, syn_packets=1, ack_packets=0, rst_packets=0)
               for p in range(1, 11)]
    refused = [make_flow(dest_port=p, syn_packets=1, ack_packets=0, rst_packets=1)
                for p in range(11, 21)]
    result = detector._analyze_source_flows("10.0.0.1", silent + refused)
    assert result is not None
    assert result.details["syn_only_count"] == 10, result.details["syn_only_count"]
    assert result.details["failed_connections"] == 20, result.details["failed_connections"]
    print("PASS: mixed silent-drop + RST-refused ports split correctly")


def test_successful_handshake_not_counted_as_failed():
    """Completed handshakes (SYN + ACK, no RST) must not count as failed."""
    detector = PortScanDetector()
    flows = [make_flow(dest_port=p, syn_packets=1, ack_packets=1, rst_packets=0)
              for p in range(1, 21)]
    result = detector._analyze_source_flows("10.0.0.1", flows)
    # Even if a result is returned (e.g. due to unique-port-count evidence),
    # neither failure counter should have picked these up.
    if result is not None:
        assert result.details["syn_only_count"] == 0, result.details["syn_only_count"]
        assert result.details["failed_connections"] == 0, result.details["failed_connections"]
    print("PASS: completed handshakes not counted as failed connections")


if __name__ == "__main__":
    tests = [
        test_syn_only_no_response_counts_as_syn_only,
        test_rst_refused_counts_as_failed_but_not_syn_only,
        test_mixed_signatures_split_correctly,
        test_successful_handshake_not_counted_as_failed,
    ]
    failures = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failures += 1
            print(f"FAIL: {t.__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    if failures:
        sys.exit(1)
