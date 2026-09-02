import pytest

scapy = pytest.importorskip("scapy")

from src.ingest.live_capture import LivePacketCapture


def test_live_capture_queue_is_bounded():
    capture = LivePacketCapture(queue_size=2, retain_packets=False)
    assert capture.packet_queue.maxsize == 2
    assert capture.get_statistics()["queue_capacity"] == 2


def test_live_capture_rejects_invalid_queue_size():
    with pytest.raises(ValueError):
        LivePacketCapture(queue_size=0)
