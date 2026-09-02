"""
Spoofing-Likelihood Evidence
==============================
Combines source-IP diversity/concentration signals (from
`src/features/source_stats.py`) into a single `spoofing_likelihood`
score and label for a set of flows.

**This is evidence, not a determination.** Nothing in this module ever
claims a source IS spoofed. Passive flow data alone cannot prove
spoofing (that would require access to the actual routing infrastructure
or return-path verification, neither of which a passive capture has).
What this module CAN do is combine several imperfect signals that
correlate with spoofed-source traffic and report a likelihood score plus
which specific signals contributed and why -- so a human or a downstream
detector can weigh it appropriately alongside other evidence.

## Signals used, and why

1. **source_entropy** (from `source_stats.calculate_source_stats`) --
   normalized Shannon entropy of PACKET VOLUME across sources. High
   entropy here means traffic is spread thinly and evenly across many
   sources rather than dominated by a few real, persistent hosts. This
   alone is weak evidence (a legitimate CDN or NAT gateway can look
   similar) which is exactly why it's combined with the other signals
   below rather than used in isolation.

2. **one_packet_source_ratio** (from `source_stats.calculate_source_stats`)
   -- fraction of distinct sources that contributed exactly one packet
   total in this window. Real, persistent hosts on the open Internet
   rarely show up as a single lone packet; a high ratio of one-packet
   "sources" is a stronger signal that many of the observed source IPs
   are not real, reachable hosts a normal handshake could complete with
   -- consistent with, but not proof of, spoofing.

3. **destination_concentration** (`source_stats.calculate_concentration`
   applied to destination IPs) -- spoofed-source floods are almost
   always aimed at a small number of targets (usually one). High source
   diversity paired with LOW destination concentration looks more like
   ordinary distributed traffic to many destinations (e.g. general
   Internet browsing, a NAT gateway) than like an attack; the same
   source diversity paired with HIGH destination concentration is a much
   stronger combined signal. This is why destination concentration is
   included as a corroborating signal rather than scored alone.

4. **source_churn** -- NOT YET AVAILABLE. Requires the streaming/
   windowing mechanism (docs/NEXT_AGENT_PROMPT.md item 6) to observe
   sources appearing/disappearing across successive windows. Always
   reported as an unavailable signal here (see `signals_unavailable` in
   the return value) rather than silently dropped or faked with a
   single-window guess. When item 6 lands, wire real churn into this
   function's weighting -- don't invent a substitute in the meantime.

## Weighting

Each available signal has a fixed weight (`SIGNAL_WEIGHTS` below). The
final score is a weighted average over ONLY the signals that were
actually computable this call, renormalized so the weights of the
available signals sum to 1.0 -- an unavailable signal (currently just
churn) is excluded from the sum rather than treated as contributing 0,
which would silently bias the score toward "not spoofed" every time.
This is a documented, deterministic rule-based combination, not a
calibrated probability model -- do not present `spoofing_likelihood` as
a probability with statistical guarantees.
"""

import logging
from typing import Any, Dict, Iterable, List, Optional

from src.features.source_stats import calculate_source_stats, calculate_concentration

logger = logging.getLogger(__name__)

# Fixed, documented weights for each signal (see module docstring for the
# rationale behind each one). Must sum to 1.0 across ALL signals,
# including currently-unavailable ones (source_churn) -- the weights of
# whichever signals ARE available get renormalized to sum to 1.0 at call
# time; see `_weighted_average` below.
SIGNAL_WEIGHTS = {
    "source_entropy": 0.25,
    "one_packet_source_ratio": 0.35,
    "destination_concentration": 0.25,
    "source_churn": 0.15,
}

# Minimum number of distinct sources before a spoofing-likelihood score
# is even meaningful. Below this, a "high entropy" or "high one-packet
# ratio" reading is just noise from a tiny sample, not evidence of
# anything. This is a documented prototype calibration choice (like
# MIN_WINDOW_SECONDS in window_rates.py), not a claim about a "correct"
# statistical threshold.
MIN_SOURCES_FOR_SCORE = 5


def _label_for_score(score: float) -> str:
    """
    Map a 0-1 score to a coarse label. Deliberately uses hedged language
    ("evidence_of_..." style would be even more explicit, but these
    labels are already non-committal) -- never "spoofed"/"not_spoofed".
    """
    if score >= 0.7:
        return "high"
    elif score >= 0.4:
        return "medium"
    elif score >= 0.15:
        return "low"
    else:
        return "minimal"


def _weighted_average(signal_values: Dict[str, float]) -> float:
    """
    Weighted average over exactly the signals present in `signal_values`
    (i.e. the ones that were computable), renormalizing weights so they
    sum to 1.0 over just those signals. Caller guarantees every key in
    `signal_values` has a matching entry in SIGNAL_WEIGHTS.
    """
    total_weight = sum(SIGNAL_WEIGHTS[name] for name in signal_values)
    if total_weight == 0:
        return 0.0
    return sum(
        value * SIGNAL_WEIGHTS[name] for name, value in signal_values.items()
    ) / total_weight


def calculate_spoofing_likelihood(flows: Iterable[Any]) -> Dict[str, Any]:
    """
    Compute spoofing-likelihood evidence for a set of flows (typically
    all flows toward one destination, or one observation window).

    Returns a dict with:
        - spoofing_likelihood (Optional[float]): 0-1 weighted score, or
          `None` if there isn't enough data to compute one at all (no
          flows, or fewer than MIN_SOURCES_FOR_SCORE distinct sources).
          `None` here means "cannot assess", NOT "zero evidence of
          spoofing" -- do not treat it as a low score.
        - spoofing_likelihood_label (str): one of "insufficient_data",
          "minimal", "low", "medium", "high". Never "spoofed"/"not_spoofed".
        - evidence (Dict[str, float]): the raw value of each AVAILABLE
          signal that fed the score (source_entropy,
          one_packet_source_ratio, destination_concentration), for
          transparency/debuggability.
        - signals_used (List[str]): which signals actually contributed.
        - signals_unavailable (Dict[str, str]): signal name -> reason,
          for signals that could not be computed this call (currently
          always includes "source_churn": "requires_streaming_window").
        - unique_source_count (int): sample size context, so callers can
          judge how much to trust the score.
    """
    flows = list(flows)

    signals_unavailable = {"source_churn": "requires_streaming_window"}

    if not flows:
        return {
            "spoofing_likelihood": None,
            "spoofing_likelihood_label": "insufficient_data",
            "evidence": {},
            "signals_used": [],
            "signals_unavailable": signals_unavailable,
            "unique_source_count": 0,
        }

    source_stats = calculate_source_stats(flows)
    unique_source_count = source_stats["unique_source_count"]

    if unique_source_count < MIN_SOURCES_FOR_SCORE:
        return {
            "spoofing_likelihood": None,
            "spoofing_likelihood_label": "insufficient_data",
            "evidence": {},
            "signals_used": [],
            "signals_unavailable": {
                **signals_unavailable,
                "source_entropy": (
                    f"only {unique_source_count} distinct source(s) seen; "
                    f"need at least {MIN_SOURCES_FOR_SCORE} for a meaningful score"
                ),
                "one_packet_source_ratio": (
                    f"only {unique_source_count} distinct source(s) seen; "
                    f"need at least {MIN_SOURCES_FOR_SCORE} for a meaningful score"
                ),
            },
            "unique_source_count": unique_source_count,
        }

    destination_concentration = calculate_concentration(
        [f.destination_ip for f in flows]
    )

    signal_values: Dict[str, float] = {
        "destination_concentration": destination_concentration,
    }

    # source_entropy can legitimately be None (e.g. all flows carried 0
    # packets) even with enough distinct sources -- exclude it from the
    # weighted average rather than treating None as 0.
    if source_stats["source_entropy"] is not None:
        signal_values["source_entropy"] = source_stats["source_entropy"]
    else:
        signals_unavailable["source_entropy"] = "no packet-volume data available"

    if source_stats["one_packet_source_ratio"] is not None:
        signal_values["one_packet_source_ratio"] = source_stats["one_packet_source_ratio"]
    else:
        signals_unavailable["one_packet_source_ratio"] = "no packet-volume data available"

    score = _weighted_average(signal_values)

    return {
        "spoofing_likelihood": score,
        "spoofing_likelihood_label": _label_for_score(score),
        "evidence": dict(signal_values),
        "signals_used": sorted(signal_values.keys()),
        "signals_unavailable": signals_unavailable,
        "unique_source_count": unique_source_count,
    }
