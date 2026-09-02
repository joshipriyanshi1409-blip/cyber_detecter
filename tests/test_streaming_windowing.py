from dataclasses import dataclass

from src.streaming.windowing import SlidingWindow, WindowAggregator


@dataclass
class Flow:
    source_ip: str
    bidirectional_first_seen_ms: int
    bidirectional_packets: int = 1
    bidirectional_bytes: int = 100


def test_bounded_expiration():
    w = SlidingWindow(window_seconds=10, slide_seconds=5)
    w.add(Flow("a", 0))
    w.add(Flow("b", 5000))
    assert w.size() == 2
    w.add(Flow("c", 16000))
    assert w.size() == 1
    assert w.active_flows()[0].source_ip == "c"
    assert w.expired_total == 2


def test_sliding_emits_at_slide_interval():
    w = SlidingWindow(window_seconds=10, slide_seconds=5)
    assert w.add(Flow("a", 0)) == []
    snapshots = w.add(Flow("b", 5000))
    assert len(snapshots) == 1
    assert snapshots[0].end_ms == 5000
    snapshots = w.add(Flow("c", 10000))
    assert [x.end_ms for x in snapshots] == [10000]


def test_source_churn_is_symmetric_difference_over_union():
    agg = WindowAggregator(window_seconds=10, slide_seconds=5)
    assert agg.add(Flow("a", 0)) == []
    first = agg.add(Flow("b", 5000))[0]
    assert first["source_churn"] is None
    second = agg.add(Flow("c", 10000))[0]
    # Previous sources {a,b}; current {a,b,c}; churn = 1/3.
    assert abs(second["source_churn"] - (1/3)) < 1e-9


def test_missing_timestamps_do_not_break_event_time_window():
    w = SlidingWindow(window_seconds=10, slide_seconds=5)
    @dataclass
    class NoTimestamp:
        source_ip: str
    assert w.add(NoTimestamp("x")) == []
    assert w.untimestamped_count == 1


if __name__ == "__main__":
    test_bounded_expiration()
    test_sliding_emits_at_slide_interval()
    test_source_churn_is_symmetric_difference_over_union()
    test_missing_timestamps_do_not_break_event_time_window()
    print("test_streaming_windowing.py: 4/4 passed")
