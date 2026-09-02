"""
Source-IP Statistics
=====================
Dedicated, independently-tested functions for computing source-IP
diversity/concentration statistics over a set of flows.

This module exists to give multiple future detectors (DDoS, port-scan,
spoofing-likelihood, SYN-flood, UDP-flood/reflection) a single, tested
source of truth for "how spread out or concentrated are the sources in
this window", instead of each detector reimplementing its own version.

Two related-but-DIFFERENT numbers live here and must stay separate
outputs, never collapsed into one (see docs/NEXT_AGENT_PROMPT.md item 1):

- **source_concentration** (Herfindahl-Hirschman Index, normalized 0-1):
  extracted verbatim from the HHI implementation that used to be private
  to `src/detectors/ddos.py` (`DDoSDetector._calculate_concentration`).
  It measures concentration over raw per-flow SOURCE-IP OCCURRENCE (one
  entry per flow, not weighted by packet/byte volume). This preserves the
  exact behavior `ddos.py` already relied on -- see `calculate_concentration`.

- **source_entropy** (normalized Shannon entropy, 0-1): measures diversity
  over the PACKET-VOLUME distribution across sources (how much traffic
  volume, not how many flows, each source is responsible for). A source
  with one giant flow and a source with one tiny flow look identical to
  the flow-occurrence-based concentration figure above, but very
  different to entropy computed on packet volume. Both figures are kept
  in the returned dict so callers can reason about flow-count skew and
  traffic-volume skew independently. See `shannon_entropy_normalized`.

**IMPORTANT (Rule 28 / missing-vs-zero, carried over from window_rates.py):**
functions here return `None` for statistics that are genuinely undefined
(e.g. no flows at all), never a fabricated `0.0`. A concentration/entropy
of `0.0` is a real, meaningful measurement (perfectly even distribution);
`None` means "we have nothing to measure". Callers must not conflate them.

**Source churn is explicitly NOT implemented here.** Detecting sources
appearing/disappearing across successive windows requires a real
sliding-window mechanism (see docs/NEXT_AGENT_PROMPT.md item 6, not yet
built). `calculate_source_stats` reports `source_churn: None` with
`source_churn_reason: "requires_streaming_window"` rather than silently
omitting it or fabricating a value -- do not "fix" this by inventing a
single-window approximation; wire it up properly once the windowing
mechanism exists.

**This module makes no "spoofing" claims.** High source diversity/
concentration is EVIDENCE that a future spoofing-likelihood detector can
use alongside other signals (see docs/NEXT_AGENT_PROMPT.md item 2) -- it
is not, by itself, a spoofing determination.
"""

import logging
import math
from collections import defaultdict
from typing import Any, Dict, Iterable, Optional

logger = logging.getLogger(__name__)


def calculate_concentration(values: Iterable[Any]) -> float:
    """
    Calculate concentration using the normalized Herfindahl-Hirschman Index
    (HHI) over raw occurrences of `values` (e.g. one entry per flow).

    This is the same algorithm that used to live as
    `DDoSDetector._calculate_concentration` in `src/detectors/ddos.py`,
    extracted here so it can be shared by any detector that needs a
    concentration figure (source diversity, destination concentration,
    port concentration, etc.) -- see docs/NEXT_AGENT_PROMPT.md item 1.
    Behavior is unchanged from the original: `ddos.py` now imports this
    function instead of maintaining its own copy.

    Returns a value in [0, 1]: 0 means values are spread perfectly evenly
    across all distinct categories present, 1 means everything is
    concentrated in a single category. Returns 0.0 for empty input --
    unlike the entropy/full-stats functions below, this is intentionally
    kept as a plain float (not Optional) since it was already relied on
    that way by `ddos.py` call sites; new callers wanting the missing-vs-
    zero distinction should check `len(values) == 0` themselves first.
    """
    values = list(values)
    if not values:
        return 0.0

    value_counts: Dict[Any, int] = defaultdict(int)
    for value in values:
        value_counts[value] += 1

    total = len(values)

    # Herfindahl-Hirschman Index
    hhi = sum((count / total) ** 2 for count in value_counts.values())

    # Normalize HHI to 0-1 range
    n = len(value_counts)
    if n <= 1:
        return 1.0

    return (hhi - 1 / n) / (1 - 1 / n)


def shannon_entropy_normalized(counts: Iterable[int]) -> Optional[float]:
    """
    Normalized Shannon entropy (0-1) of a distribution given as raw counts
    (e.g. packets-per-source values), base determined by the number of
    distinct non-zero categories so the result is comparable across
    windows with different numbers of sources.

    Returns:
        - `None` if there is no data at all (empty input or all-zero
          counts) -- entropy is undefined here, this is NOT the same as
          "perfectly even" (see Rule 28 / missing-vs-zero).
        - `0.0` if there is exactly one category with nonzero count --
          this IS a meaningful, defined value (zero diversity), not
          "missing".
        - Otherwise, entropy normalized to [0, 1] where 1.0 is a
          perfectly even distribution across all distinct categories and
          values closer to 0 mean the distribution is dominated by very
          few categories.
    """
    counts = [c for c in counts if c > 0]
    if not counts:
        return None

    n = len(counts)
    if n == 1:
        return 0.0

    total = sum(counts)
    raw_entropy = 0.0
    for c in counts:
        p = c / total
        raw_entropy -= p * math.log(p, 2)

    max_entropy = math.log(n, 2)
    if max_entropy == 0:
        # Unreachable given the n == 1 check above, but guard anyway
        # rather than risk a ZeroDivisionError from a future refactor.
        return 0.0

    return raw_entropy / max_entropy


def calculate_source_packet_distribution(flows: Iterable[Any]) -> Dict[str, int]:
    """Total bidirectional packets attributable to each source IP."""
    distribution: Dict[str, int] = defaultdict(int)
    for flow in flows:
        distribution[flow.source_ip] += flow.bidirectional_packets
    return dict(distribution)


def calculate_source_byte_distribution(flows: Iterable[Any]) -> Dict[str, int]:
    """Total bidirectional bytes attributable to each source IP."""
    distribution: Dict[str, int] = defaultdict(int)
    for flow in flows:
        distribution[flow.source_ip] += flow.bidirectional_bytes
    return dict(distribution)


def calculate_source_stats(flows: Iterable[Any]) -> Dict[str, Any]:
    """
    Compute source-IP diversity/concentration statistics for a set of
    flows (typically all flows in one observation window).

    Returns a dict with:
        - unique_source_count (int)
        - total_packets (int)
        - source_packet_distribution (Dict[str, int])
        - source_byte_distribution (Dict[str, int])
        - top_source_ip (Optional[str])
        - top_source_fraction (Optional[float]) -- fraction of total
          packets attributable to the single largest source, by packet
          volume. `None` (not 0.0) when there is no traffic to measure.
        - source_entropy (Optional[float]) -- see
          `shannon_entropy_normalized`; computed over packet VOLUME per
          source.
        - source_concentration (float) -- see `calculate_concentration`;
          computed over per-flow source-IP OCCURRENCE (flow count, not
          packet volume). Deliberately a different basis than
          source_entropy above -- see module docstring.
        - one_packet_source_count (int) -- sources whose TOTAL packet
          contribution across all flows in this window is exactly 1.
          A high count/ratio of these is one candidate signal (among
          several) for a future spoofing-likelihood detector.
        - one_packet_source_ratio (Optional[float])
        - source_churn (None) -- always None here; see module docstring.
        - source_churn_reason (str) -- explains why, so callers don't
          mistake the None for a bug.
    """
    flows = list(flows)

    if not flows:
        return {
            "unique_source_count": 0,
            "total_packets": 0,
            "source_packet_distribution": {},
            "source_byte_distribution": {},
            "top_source_ip": None,
            "top_source_fraction": None,
            "source_entropy": None,
            "source_concentration": 0.0,
            "one_packet_source_count": 0,
            "one_packet_source_ratio": None,
            "source_churn": None,
            "source_churn_reason": "requires_streaming_window",
        }

    packet_distribution = calculate_source_packet_distribution(flows)
    byte_distribution = calculate_source_byte_distribution(flows)

    unique_source_count = len(packet_distribution)
    total_packets = sum(packet_distribution.values())

    if total_packets > 0:
        top_source_ip, top_source_packets = max(
            packet_distribution.items(), key=lambda kv: kv[1]
        )
        top_source_fraction = top_source_packets / total_packets
    else:
        # Sources exist (flows are non-empty) but carried zero packets --
        # a degenerate/malformed-flow case. Don't fabricate a fraction.
        top_source_ip = None
        top_source_fraction = None

    source_entropy = shannon_entropy_normalized(packet_distribution.values())

    # Flow-occurrence-based concentration, matching the pre-existing
    # ddos.py definition exactly (one entry per flow's source_ip).
    source_concentration = calculate_concentration([f.source_ip for f in flows])

    one_packet_sources = [ip for ip, pkts in packet_distribution.items() if pkts == 1]
    one_packet_source_count = len(one_packet_sources)
    one_packet_source_ratio = (
        one_packet_source_count / unique_source_count if unique_source_count > 0 else None
    )

    return {
        "unique_source_count": unique_source_count,
        "total_packets": total_packets,
        "source_packet_distribution": packet_distribution,
        "source_byte_distribution": byte_distribution,
        "top_source_ip": top_source_ip,
        "top_source_fraction": top_source_fraction,
        "source_entropy": source_entropy,
        "source_concentration": source_concentration,
        "one_packet_source_count": one_packet_source_count,
        "one_packet_source_ratio": one_packet_source_ratio,
        "source_churn": None,
        "source_churn_reason": "requires_streaming_window",
    }
