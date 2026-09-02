# CyberDetecter Audit Progress Report

This document tracks progress against the full repository audit/repair/hardening
brief. It exists so any engineer (human or AI) picking up this work has an
accurate record of what's actually been done, verified, and what remains.

**Sandbox limitation, always true so far:** all work has been done in an
environment with NO network access, so `nfstream`, `scapy`, and `pytest`
cannot be installed there. Every fix below has been verified as thoroughly
as possible without those packages (algorithm simulations, dependency-free
unit tests, stub-based import checks, manual test-collection). Anything
that genuinely requires those packages is explicitly flagged as
**NEEDS VERIFICATION ON A MACHINE WITH NFSTREAM/SCAPY/PYTEST INSTALLED**.

---

## STEP 1 — Repository Audit (COMPLETE)

76 Python files across ingest/flow/features/detectors/scoring/alerts/storage/
streaming/blockchain/cti/models/dashboard. Traced the core pipeline:
PCAP → flow extraction → DDoS detection → alert.

### Confirmed bugs (see git history / diffs for exact fixes)

1. **DDoS aggregate rate bug** (`src/detectors/ddos.py`, now FIXED) — used
   `sum(flow.duration)` as the rate denominator instead of the shared
   observation window. Empirically reproduced: for 100 simultaneous 100ms
   flows @ 1000 packets each, old code reported 10,000 pps; correct answer
   is 1,000,000 pps. This exact scenario is now a regression test
   (`tests/test_window_rates.py::test_thE_section_26_regression_case`).

2. **Flow directionality bug** (`src/flow/nfstream_wrapper.py`
   `_extract_with_scapy`, now FIXED) — every packet was written into
   `src2dst_*` regardless of true direction, `dst2src_*` was hardcoded to
   `0`, and A→B / B→A were tracked as two separate "flows" instead of one
   bidirectional flow. Fixed with flow-key canonicalization + true
   initiator-relative direction tracking. Verified with a scapy-free
   simulation of the algorithm (2/2 checks pass); **the scapy-specific
   packet-parsing code itself still needs verification with real scapy**.

3. **ICMP silently dropped** in the Scapy fallback — FIXED, now tracked
   (`icmp_packets`, `icmp_bytes`, `icmp_type_counts` on `FlowRecord`).

4. **SYN-only vs SYN-ACK conflated** — the existing `syn_packets` field
   counts ANY SYN-flagged packet (NFStream convention, left unchanged for
   compatibility). Added `syn_only_packets` / `syn_ack_packets` as new
   fields so future detectors can distinguish them. **Nothing consumes
   these new fields yet — that's the next major piece of work (Section 7
   of the original brief, SYN-flood-specific detection).**

5. **Timestamp semantics bug** — all three FlowRecord construction paths
   used `time.time()` (processing time) as the flow's `timestamp` field
   instead of the flow's actual traffic/capture time. FIXED in all three
   (`_dataframe_to_flow_records`, `_nfstream_flow_to_record`,
   `_extract_with_scapy`).

6. **Hard `nfstream` import** — the whole module, including the plain
   `FlowRecord` dataclass, failed to import without nfstream installed,
   which defeated the purpose of having a Scapy fallback at all. FIXED:
   lazy/optional import with `NFSTREAM_AVAILABLE` flag; `extract_from_pcap`
   now routes straight to the Scapy fallback when nfstream is absent;
   `extract_from_live` raises a clear `RuntimeError` (no fallback exists
   for live capture).

7. **Dead/duplicated condition in `src/detectors/scan.py`** (lines ~161,
   164) — an `if`/`elif` with the IDENTICAL condition
   (`flow.syn_packets > 0 and flow.ack_packets == 0`), making the `elif`
   branch unreachable dead code. **NOT YET FIXED** — likely meant to check
   `rst_packets > 0` for a different failure signature. Flagged, not
   touched (out of scope for the flow-model/DDoS-rate pass).

8. **Placeholder/empty files**: `docker/Dockerfile`, `docker/docker-compose.yml`,
   `docs/ARCHITECTURE.md`, `docs/THREAT-MODELS.md`, `setup.py`,
   `requirements-lock.txt` are all 0 bytes. 3 of 4 demo PCAPs
   (`ddos.pcap`, `dga.pcap`, `normal.pcap`) are 0 bytes; only
   `port_scan.pcap` has content. **NOT YET ADDRESSED.**

9. **`tests/confest.py`** — typo, should be `conftest.py`. Pytest silently
   never loads it (its `sys.path` setup and warning filters never apply).
   **NOT YET FIXED** — trivial rename, but wanted to flag it clearly since
   it may explain otherwise-confusing test import failures on a real
   pytest run.

10. **No real streaming/windowing mechanism exists.** `src/streaming/pipeline.py`
    only has whole-PCAP batch processing (`process_pcap`) and a live-capture
    method; there is no sliding-window / ring-buffer abstraction anywhere.
    **NOT YET BUILT** — this is Section 5 of the original brief and is a
    prerequisite for real streaming DDoS detection.

11. **Confidence/risk_score conflation** in `ddos.py` — `risk_score` is
    just `confidence * 100` where `confidence` is a rule-based weighted
    sum; there's no separate `rule_score` vs `ml_probability` field.
    **NOT YET FIXED.**

12. **`source_ip` hardcoded to `"multiple_sources"`** in DDoS alerts, with
    no source count/entropy attached at the top level (source_count is now
    included in `details`, but the alert schema itself wasn't restructured
    per Section 15 of the brief). **PARTIALLY ADDRESSED** (source_count
    added to details dict), full alert schema rebuild NOT done.

---

## STEP 5 (partial) — DDoS Rate Fix (COMPLETE for aggregate rate math)

**New file:** `src/features/window_rates.py` — dedicated, dependency-free,
fully-tested window-based rate calculation:
- `compute_window_bounds(flows)` — derives shared observation window from
  flow timestamps, returns `(None, None)` (not `0`) when unavailable.
- `calculate_window_rates(...)` — packets/sec, bytes/sec, flows/sec, with
  documented zero/tiny-window clamping (`MIN_WINDOW_SECONDS = 0.001`) and
  explicit `window_clamped` flag so callers/alerts stay honest about it.
- `calculate_rates_for_flows(flows)` — convenience wrapper most detectors
  should call.

**New test file:** `tests/test_window_rates.py` — 9/9 passing, dependency-free
(runs with plain `python3 tests/test_window_rates.py`, no pytest needed).
Covers: the exact Section-26 regression case, single flow, sequential,
overlapping, zero-duration (doesn't fabricate 0), missing timestamps
(returns `None` not `0`), many-flows-tiny-window, empty input, malformed
end-before-start timestamps.

**`src/detectors/ddos.py` rewired** to use the new module in all three
places that previously duplicated the buggy calculation
(`_analyze_aggregate_traffic`, `_analyze_destination_flows`,
`get_flood_statistics`). Removed dead `FlowRateCalculator` instantiation
that was imported but never actually called.

**Verification performed:**
- 16/16 existing `tests/test_detectors.py` tests pass (manually collected
  and run — see note below on the harness).
- Empirically confirmed exact regression case now reports correct
  1,000,000 pps (was 10,000 pps).
- Whole `src/`, `scripts/`, `dashboard/`, `models/` trees pass
  `py_compile` (no syntax errors introduced anywhere).
- Import-level check on every module touched or downstream of touched
  code (`src.flow.*`, `src.detectors.*`, `src.features.*`,
  `src.scoring.risk_score`, `src.alerts.*`) — all import cleanly.
  `src.streaming.pipeline` fails on `ModuleNotFoundError: sqlalchemy` —
  **pre-existing, unrelated to this work, confirmed by checking it fails
  the same way before any of these changes too.**

**Test-harness caveat:** since `pytest` isn't installed in this sandbox,
verification of pytest-based test files was done by hand-rolling a
minimal test collector (instantiate each `Test*` class, call each
`test_*` method). This is NOT a substitute for a real `pytest` run — it
doesn't handle `@pytest.fixture` injection, doesn't call
`setup_method`/`teardown_method` automatically (had to be done manually
where needed), and doesn't replicate pytest's assertion rewriting. Treat
the pass counts here as a strong signal, not a certification. **Run the
real `pytest tests/ -v` on a properly-provisioned machine before treating
this as done.**

**NOT covered by this pass** (still using flat `confidence_factors` list,
no separate rule_score/ml_probability, no source-IP entropy/HHI/churn
stats, no SYN-flood-specific detector, no UDP-specific detector, no
reflection-likelihood evidence, no evidence-fusion model) — see the
handoff prompt for the next agent for the precise remaining scope.

---

## Files changed in this pass

- `src/flow/nfstream_wrapper.py` (modified)
- `src/detectors/ddos.py` (modified)
- `src/features/window_rates.py` (new)
- `tests/test_window_rates.py` (new)
- `docs/AUDIT_PROGRESS.md` (this file, new)
- `docs/NEXT_AGENT_PROMPT.md` (new — handoff instructions)

No other files were modified. No files were deleted.

---

## STEP 2 — Continuation pass (this pass)

**Sandbox limitation, still true:** confirmed again at the start of this
pass — `pip install nfstream scapy pytest --break-system-packages` fails
with "No matching distribution found" (no network egress). Every
`tests/test_*.py` file that predates this pass imports `pytest` at module
level (several also import `scapy` at module level), so **none of them
can even be collected/imported in this sandbox**, let alone run under a
real `pytest`. This means the "16/16 `tests/test_detectors.py` tests
pass (manually collected)" claim from the previous pass could not be
reproduced or re-verified here — there is no evidence one way or the
other in this environment. Treat that earlier claim as unverified until
someone runs it on a real machine with `pytest`/`scapy` installed. All
verification in this pass, like the last, used dependency-free scripts
(`python3 tests/test_X.py`, no pytest) plus direct `py_compile` /
import-checks.

### 1. Source-IP statistics module (original brief Section 6.3) — DONE

**New file:** `src/features/source_stats.py` — dedicated, dependency-free
module computing, for a set of flows:
- `unique_source_count`, `total_packets`
- `source_packet_distribution` / `source_byte_distribution` (per-source
  totals)
- `top_source_ip` / `top_source_fraction` (by packet volume; `None`, not
  0, when there's no traffic to measure)
- `source_entropy` — normalized Shannon entropy (0-1) of the **packet-
  volume** distribution across sources. Returns `None` (not 0.0) when
  there's no data at all; 0.0 is a real, defined value (single source).
- `source_concentration` — normalized HHI, but over per-flow
  **source-IP occurrence** (flow count), not packet volume. This is a
  deliberately different basis from `source_entropy` above — see the
  module docstring for why they're kept separate rather than collapsed
  into one number.
- `one_packet_source_count` / `one_packet_source_ratio` — candidate
  signal (not a determination) for a future spoofing-likelihood
  detector.
- `source_churn` — explicitly `None` with `source_churn_reason:
  "requires_streaming_window"`. NOT implemented (needs item 6 first);
  deliberately not stubbed with a fake single-window approximation.

`calculate_concentration(values)` is the exact HHI algorithm that used to
be a private method (`_calculate_concentration`) — extracted so it's
shared instead of duplicated. `shannon_entropy_normalized(counts)` is the
new entropy primitive, kept separate from concentration per the brief.

**New test file:** `tests/test_source_stats.py` — 8/8 passing,
dependency-free (`python3 tests/test_source_stats.py`). Covers: empty
input (missing-vs-zero for every field), single dominant source,
perfectly even distribution, dominant-source-plus-one-packet-tail (the
classic spoofed-source-DDoS shape), degenerate zero-packet flows, a
direct regression check that the extracted HHI math reproduces the exact
figures the pre-refactor implementation produced, Shannon-entropy edge
cases, and the distribution helpers.

### Deduplication found and fixed (was not in original scope, discovered while doing item 1)

The brief flagged one `_calculate_concentration` private copy in
`ddos.py`. Grepping the whole repo for that name before touching
anything (per the handoff's Rule "grep the WHOLE repo before declaring a
change safe") turned up **two more copies** of the identical HHI
algorithm, both in `src/features/network_features.py`
(`NetworkFeatureExtractor._calculate_concentration`, used at 4 call
sites: `source_concentration`/`destination_concentration`/
`port_concentration` in `extract_aggregate_features`, and
`dest_concentration` inside `_calculate_syn_flood_score`).

All three private copies (1 in `ddos.py`, 1 in `network_features.py` —
the method definition was one copy, called from 4 sites) were replaced
with imports of the new shared `calculate_concentration` from
`src/features/source_stats.py`. Behavior is unchanged — verified three
ways:
1. `tests/test_source_stats.py::test_concentration_matches_original_ddos_py_hhi_values`
   reproduces known HHI figures by hand-computed expected values.
2. Grepped `src/`, `scripts/`, `dashboard/`, `tests/`, `models/` for
   `_calculate_concentration` after removal — zero live references left
   (only docstring/comment mentions of the pre-refactor name for
   context).
3. Functional smoke test: ran `DDoSDetector.detect()`,
   `DDoSDetector.get_flood_statistics()`, and
   `NetworkFeatureExtractor.extract_aggregate_features()` against
   synthetic flows (various source-distribution shapes: single source,
   evenly spread across 20 sources, spoofed-tail shape) and confirmed
   `source_concentration` / `destination_concentration` /
   `port_concentration` values match expected HHI results (0.0 for
   perfectly even, 1.0 for single-value, etc.).

**Files touched:** `src/detectors/ddos.py` (import added, 1 private
method removed, 3 call sites updated), `src/features/network_features.py`
(import added, 1 private method removed, 4 call sites updated). No
behavior change intended or observed; only the DDoS aggregate-rate logic
from STEP 1 was already touched in `ddos.py` before this pass — this
pass's edits to `ddos.py` are additive/orthogonal (concentration
delegation only).

**Verification performed for this whole item:**
- `python3 -m py_compile` on the touched files individually, then swept
  the whole `src/`, `scripts/`, `dashboard/`, `models/` trees — no syntax
  errors anywhere.
- Import-checked `src.detectors.ddos`, `src.features.network_features`,
  and everything that imports them
  (`src.detectors.detector_factory`, `src.alerts.alert_engine`) — all
  import cleanly (`nfstream` absence correctly falls back, as before).
- **NOT covered:** a real `pytest` run of `tests/test_features.py` /
  `tests/test_detectors.py` (both import `scapy`/`pytest` at module
  level, unavailable here). Someone with a properly-provisioned machine
  should run `pytest tests/test_features.py tests/test_detectors.py -v`
  before treating this refactor as fully certified, even though the
  dependency-free evidence above is strong.

### 7 (partial). Small, low-risk fixes — 2 of 3 DONE

- **`tests/confest.py` → `tests/conftest.py`** — DONE. Grepped repo for
  any reference to the old filename first (pytest discovers `conftest.py`
  by convention, not by import, so nothing referenced it by name) — plain
  rename, `py_compile` clean.
- **Dead `elif` in `src/detectors/scan.py`** — DONE. The old code:
  ```python
  if flow.syn_packets > 0 and flow.ack_packets == 0:
      syn_only_count += 1
      failed_connections += 1
  elif flow.syn_packets > 0 and flow.ack_packets == 0:   # identical condition, dead
      failed_connections += 1
  ```
  Confirmed via grep that `rst_packets` was never referenced anywhere in
  `scan.py` (matching the audit's hypothesis). Fixed to distinguish two
  real failure signatures: (1) SYN sent, no ACK, no RST → no response at
  all (`syn_only_count` — filtered/stealth-scan-like), (2) SYN sent, RST
  received → actively refused (`failed_connections` only, NOT
  `syn_only_count`, since a real reply was received). New test file
  `tests/test_scan_failure_signatures.py` — 4/4 passing, dependency-free.
  Checked `tests/test_detectors.py`'s scan fixtures use `rst_packets=0`
  throughout, so this fix does not change behavior for any existing
  fixture (confirmed by inspection, since that file can't be executed
  here — see sandbox note above).
- **0-byte placeholder files** (Dockerfile, docker-compose.yml,
  ARCHITECTURE.md, THREAT-MODELS.md, setup.py, requirements-lock.txt,
  3 of 4 demo pcaps) — **NOT YET ADDRESSED** this pass either. Still
  flagged, not touched.

### Files changed in this pass

- `tests/confest.py` → `tests/conftest.py` (renamed)
- `src/detectors/scan.py` (modified — dead `elif` fix)
- `src/detectors/ddos.py` (modified — concentration delegated to shared module)
- `src/features/network_features.py` (modified — concentration delegated to shared module)
- `src/features/source_stats.py` (new)
- `tests/test_source_stats.py` (new)
- `tests/test_scan_failure_signatures.py` (new)
- `docs/AUDIT_PROGRESS.md` (this section, updated)
- `docs/NEXT_AGENT_PROMPT.md` (updated — see below)

No other files were modified. No files were deleted (only the one rename
above).

### What's left after this pass

Items 3-6 and 8 from the previous handoff prompt are all still open
(SYN-flood-specific detector, UDP flood/reflection-like detection,
evidence fusion/confidence model, streaming/windowing mechanism, alert
schema rebuild) — `source_stats.py` and `spoofing_likelihood.py` from
this pass are ready building blocks for item 3. The 0-byte placeholder
files are also still open. See the updated `docs/NEXT_AGENT_PROMPT.md`
for exact next-agent instructions.

---

## STEP 3 — Continuation pass (spoofing-likelihood evidence)

**Sandbox limitation, re-confirmed at the start of this pass too:**
`pip install pytest --break-system-packages` still fails with "No
matching distribution found" — no network egress, same as both prior
passes. Nothing pytest-based can be collected here. All verification
below is dependency-free scripts + `py_compile` + import checks, same as
before.

**Re-verification of prior passes' work, done first:** before writing
any new code this pass, re-ran the full compile sweep, all three
existing dependency-free test files (21/21 still passing), re-ran the
`DDoSDetector` functional smoke test from STEP 2, re-checked for
dangling `self._calculate_concentration` references (none), and
confirmed `tests/conftest.py` / the `scan.py` fix are both still intact.
Nothing had regressed.

### 2. Spoofing-likelihood evidence (Section 6.4) — DONE

**New file:** `src/features/spoofing_likelihood.py` —
`calculate_spoofing_likelihood(flows)`, built directly on
`source_stats.calculate_source_stats` and `source_stats.calculate_concentration`
(destination-IP concentration). Combines three currently-available
signals into a weighted `spoofing_likelihood` score (0-1) plus a
non-committal label (`insufficient_data` / `minimal` / `low` / `medium`
/ `high` -- never "spoofed"/"not_spoofed"):

- `source_entropy` (packet-volume Shannon entropy across sources, from
  item 1) -- weight 0.25
- `one_packet_source_ratio` (from item 1) -- weight 0.35
- `destination_concentration` (HHI over destination IPs, reusing
  `calculate_concentration`) -- weight 0.25
- `source_churn` -- weight 0.15, but **always unavailable** right now
  (needs item 6, the streaming/windowing mechanism). Reported explicitly
  in `signals_unavailable` with reason `"requires_streaming_window"`.
  When churn is unavailable the other signals' weights are renormalized
  to sum to 1.0 -- an unavailable signal is excluded from the average,
  NOT treated as contributing 0 (that would silently bias every score
  toward "not spoofed").

Below `MIN_SOURCES_FOR_SCORE = 5` distinct sources, the function returns
`spoofing_likelihood: None` / label `"insufficient_data"` rather than a
noisy score from a tiny sample -- documented as a prototype calibration
choice, not a statistical claim (same pattern as `MIN_WINDOW_SECONDS` in
`window_rates.py`).

**New test file:** `tests/test_spoofing_likelihood.py` — 7/7 passing,
dependency-free. Covers: empty input, too-few-sources
(`insufficient_data`), the classic spoofed-flood shape (many one-packet
sources hitting one destination -- scores "high"), ordinary distributed
traffic with real multi-packet sources spread across many destinations
(scores well below 0.4 despite high source diversity, demonstrating the
weighting isn't fooled by entropy alone), a direct comparison proving
destination concentration meaningfully moves the score (validates the
weighting rationale in the docstring isn't just asserted, it's tested),
that `source_churn` is always reported as unavailable rather than
silently dropped, and a randomized-input sweep confirming the score
always stays within [0, 1].

**Not done / explicitly out of scope for this item:** this module is
NOT wired into `ddos.py` or any alert-producing detector yet -- that's
item 5 (evidence fusion), which should happen after item 3 (SYN-flood
detector) also exists, per the brief's own sequencing. Nothing currently
imports `spoofing_likelihood.py` outside its own test file; that is
expected and correct for this stage.

**Verification performed:**
- Full `py_compile` sweep of `src/`, `scripts/`, `dashboard/`, `models/`,
  `tests/` -- no syntax errors anywhere, including all prior passes'
  files.
- Import-check on the new module alone (it only depends on
  `source_stats.py`, already verified dependency-free).
- Re-ran ALL FOUR dependency-free test files together (`test_window_rates.py`,
  `test_source_stats.py`, `test_scan_failure_signatures.py`,
  `test_spoofing_likelihood.py`) -- 28/28 passing.
- Grepped the whole repo for any pre-existing "spoofing" logic this
  might duplicate or need to integrate with -- found none outside
  docstring mentions already added in STEP 2's `source_stats.py`, so no
  integration/deduplication risk here.

### Files changed in this pass

- `src/features/spoofing_likelihood.py` (new)
- `tests/test_spoofing_likelihood.py` (new)
- `docs/AUDIT_PROGRESS.md` (this section, updated)
- `docs/NEXT_AGENT_PROMPT.md` (updated — see below)

No existing files were modified in this pass (pure addition). No files
were deleted.

---

## STEP 4 — SYN-flood-specific detector (docs/NEXT_AGENT_PROMPT.md item 3)

**Sandbox limitation, re-confirmed at the start of this pass too:**
`pip install nfstream scapy pytest --break-system-packages` still fails
with "No matching distribution found" -- pip can reach an index but
there is no real package mirror behind it, so nothing installs. All
verification below is dependency-free scripts + `py_compile` + import
checks + a manual end-to-end wiring sanity check, same discipline as
every prior pass. **This was not verified with a real `pytest` run.**

**Re-verification of prior passes' work, done first:** re-ran all four
existing dependency-free test files together before writing any new
code -- 28/28 still passing, nothing had regressed.

### 3. SYN-flood-specific detector (Section 7) — DONE

**New file:** `src/detectors/syn_flood.py` -- `SynFloodDetector` /
`SynFloodResult`, the first consumer of the `syn_only_packets` /
`syn_ack_packets` fields added in STEP 1 (nothing used them before
this). Computes, per set of TCP flows: SYN-only rate
(`syn_only_packets_per_second`, via `window_rates.calculate_window_rates`
reused directly -- not reimplemented), `ack_completion_ratio`
(total ACKs / total SYN-only, i.e. how many client SYNs got a full
handshake), `syn_ack_ratio`, `rst_ratio`, and a flow-level
`incomplete_flow_ratio` (SYN sent, no ACK at all). All ratios follow
the missing-vs-zero discipline (Rule 28): `None` when the denominator
is zero (no SYN-only packets seen), never a fabricated `0.0`.

**Two-level analysis, matching the brief's instruction to combine with
destination concentration AND source diversity, not decide on either
ratio alone:**
- **Aggregate level** (all TCP flows together): SYN-only rate +
  ack-completion ratio + destination concentration (via
  `source_stats.calculate_concentration`).
- **Per-destination level** (TCP flows to one destination): SYN-only
  rate + ack-completion ratio + a source-diversity signal (see below).

**Combination rule (the actual fix for "never decide on a single ratio
alone"):** an earlier draft of this detector followed `ddos.py`'s
existing pattern of flagging as soon as ANY one factor crossed
threshold. That directly contradicts
docs/NEXT_AGENT_PROMPT.md item 3's explicit instruction. Fixed before
this was ever run: both `_analyze_aggregate_traffic` and
`_analyze_destination_flows` now require **at least 2** of their 3
possible factors to have crossed threshold before returning a
detection at all. `tests/test_syn_flood.py::test_combination_rule_requires_at_least_two_factors`
and `test_syn_heavy_legitimate_workload_not_flagged` both specifically
exercise this.

**Two real bugs found and fixed DURING verification of this pass** (not
hypothetical -- both were caught by tests in this same pass actually
failing, then fixed, then re-run green):

1. The first working version of the per-destination source-diversity
   signal called `spoofing_likelihood.calculate_spoofing_likelihood(flows)`
   directly, reusing it per docs/NEXT_AGENT_PROMPT.md item 1's
   "don't reimplement a 4th copy" guidance. This was wrong: that
   function's score includes `destination_concentration` as one of its
   weighted signals, computed as `calculate_concentration([f.destination_ip
   for f in flows])` -- but at the per-destination call site, `flows` has
   ALREADY been filtered down to one destination (that's the whole point
   of per-destination grouping), so that concentration is trivially
   `1.0` on every single call, silently inflating every per-destination
   score regardless of actual source-diversity evidence.
   `test_syn_heavy_legitimate_workload_not_flagged` failed immediately
   with a spoofing_likelihood of ~0.59 on completely ordinary,
   fully-completing handshake traffic.

2. Fix attempt #1: stopped calling the full function, instead combined
   just `source_entropy` and `one_packet_source_ratio` from
   `source_stats.calculate_source_stats(flows)` -- first with a naive
   50/50 weighting (same test still failed, score ~0.42), then with
   `spoofing_likelihood.SIGNAL_WEIGHTS`'s actual relative weights
   renormalized over just those two signals (still failed, score
   ~0.42). Root cause: `source_entropy` alone, even correctly
   down-weighted, is too weak/noisy a signal at small per-destination
   sample sizes -- a handful of real, distinct clients sending evenly
   distributed legitimate traffic to one server also produces entropy
   near 1.0 (maximally "even"), which reads identically to "many
   thinly-spread possibly-spoofed sources" without a corroborating
   destination-concentration-across-MULTIPLE-destinations signal, which
   is exactly what's structurally unavailable at this call site.
   **Final fix:** dropped `source_entropy` entirely from the
   per-destination signal; `_per_destination_spoofing_evidence` now
   uses ONLY `one_packet_source_ratio` (real, persistent hosts
   essentially never show up as exactly one packet in a window, so this
   stays meaningful even alone, unlike entropy). All 9 tests pass after
   this fix, including the one that had been catching the false
   positive.

This is exactly the kind of thing docs/NEXT_AGENT_PROMPT.md's
verification checklist (item 3 there) is for -- writing a real test for
the "should NOT flag" case, not just the "should flag" case, is what
caught both bugs. Future agents extending this file: keep that test.

**`_determine_severity`** reuses the same LOW/MEDIUM/HIGH/CRITICAL
banding style as `ddos.py`/`scan.py`, escalated one severity level when
`ack_completion_ratio < 0.05` (near-total handshake failure is stronger
evidence of saturation than rate alone).

**`rule_score` / `ml_probability` kept explicitly separate** on
`SynFloodResult`, per the audit's non-negotiable rule -- `ml_probability`
is always `None` (no ML wired in), never fabricated as `0.0`.
`confidence` currently equals `rule_score` since nothing else
contributes; a docstring note flags this so a future ML integration
doesn't silently collapse the two fields together.

**New test file:** `tests/test_syn_flood.py` -- 9/9 passing,
dependency-free. Covers: normal fully-completing handshake traffic (no
detection), a classic SYN flood (many one-packet sources, near-zero
completion, single target -- detected), a SYN-heavy-but-legitimate
workload (high rate but full completion and low concentration/diversity
evidence -- NOT detected, the specific case that caught both bugs
above), SYN-only traffic (rate + completion factors alone are
sufficient), SYN-ACK-heavy traffic (server-reply-dominated, not
SYN-only-heavy -- not detected), RST-heavy traffic (evidence reported
in `details` for transparency but NOT itself a weighted factor -- still
flagged via rate+completion when those independently cross threshold),
non-TCP flows (filtered out, no crash), the >=2-factor combination rule
in isolation, and the statistics helper's empty/non-TCP-input handling.

**Wired into `detector_factory.py`:** new `DetectorType.SYN_FLOOD`,
registered in `DetectorFactory.__init__`'s `self.detectors` dict, and
`SynFloodDetector.get_syn_flood_statistics` added to
`get_detector_statistics`. This was NOT explicitly requested by item 3's
text, but leaving a fully-built detector unregistered would mean it
never actually runs via `run_all_detectors`/`run_all_detectors_flat`
(used by `scripts/run_detection.py` and `src/streaming/pipeline.py`),
which would violate the "must never merely LOOK implemented" principle
(Section 58) the same way an empty placeholder file would. Grepped the
whole repo for existing `DetectorType.*` usage before this change --
only `PORT_SCAN`/`DDOS`/`DGA` were referenced anywhere (including
`tests/test_detectors.py`'s `isinstance` assertions), so adding a new
enum member is additive and safe; confirmed by re-checking those exact
call sites after the change.

**Config additions:** `syn_flood:` section added to
`config/thresholds.yaml` and the `"syn_flood"` key added to
`DEFAULT_THRESHOLDS` in `src/utils/config_simple.py` (both with
identical default values), matching the existing `ddos`/`port_scan`
pattern so `SynFloodDetector._load_thresholds()` has a working fallback
in both the real-config and sandbox-fallback paths.

**Verification performed:**
- Full `py_compile` sweep of `src/`, `scripts/`, `dashboard/`, `models/`,
  `tests/` (including the newly-touched `detector_factory.py` and
  `config_simple.py`) -- no syntax errors anywhere.
- Import-check on `src.detectors.syn_flood` standalone, then on
  `src.detectors.detector_factory` (which now imports it) and every
  other module downstream of touched code.
- Re-ran ALL FIVE dependency-free test files together
  (`test_window_rates.py`, `test_source_stats.py`,
  `test_scan_failure_signatures.py`, `test_spoofing_likelihood.py`,
  `test_syn_flood.py`) -- 37/37 passing, no regressions from any prior
  pass's work.
- End-to-end sanity check (not a formal test file, run manually and
  recorded here): instantiated `DetectorFactory`, confirmed
  `SYN_FLOOD` appears in `self.detectors`, ran `run_all_detectors()`
  and `get_detector_statistics()` on a small synthetic flow list built
  directly (not via a `FakeFlow` matching the real `FlowRecord` field
  set) -- both returned without error and with a `"syn_flood"` key
  present in their results, confirming the wiring itself (not just the
  detector in isolation) works.
- Grepped the whole repo for `DetectorType.SYN_FLOOD` / `SynFloodDetector`
  / `SynFloodResult` after the change -- only appear in
  `src/detectors/syn_flood.py`, `src/detectors/detector_factory.py`,
  and `tests/test_syn_flood.py`, as expected; no stray/duplicate
  wiring elsewhere.

**NOT covered by this pass:**
- A real `pytest` run of `tests/test_syn_flood.py` or any pre-existing
  pytest-based test file -- same sandbox limitation as every prior
  pass. Someone with `nfstream`/`scapy`/`pytest` installed should run
  `pytest tests/ -v` before treating this as fully certified.
- Item 4 (UDP flood + reflection-like detection) -- not started.
- Item 5 (evidence fusion / confidence model rebuild for `ddos.py`) --
  not started; `syn_flood.py` uses its own flat-but-gated
  (`>=2 factors`) confidence_factors list, not a shared evidence-fusion
  model, since item 5 hasn't been built yet. When item 5 lands, revisit
  whether `syn_flood.py` should be migrated onto it too.
- Item 6 (streaming/windowing) -- still not built; `source_churn`
  remains unavailable everywhere it's referenced, unchanged from STEP 2/3.
- Item 7's remaining piece (0-byte placeholder files, 3 of 4 empty demo
  PCAPs) -- still open, not touched this pass.
- Item 8 (alert schema rebuild) -- correctly still deferred; this pass
  did not touch `Alert`/`AlertBatch` in `src/alerts/alert_models.py`.
  `SynFloodResult` was deliberately given the exact same shape as
  `DDoSResult`/`PortScanResult` (`to_dict()`, `threat_type`,
  `source_ip`, etc.) so it flows through the existing generic
  `AlertEngine._detection_to_alert` path unchanged -- confirmed by
  reading `src/alerts/alert_engine.py`, which never special-cases
  per-detector result types.

### Files changed in this pass

- `src/detectors/syn_flood.py` (new)
- `tests/test_syn_flood.py` (new)
- `src/detectors/detector_factory.py` (modified -- registered
  `DetectorType.SYN_FLOOD` / `SynFloodDetector`)
- `config/thresholds.yaml` (modified -- added `syn_flood:` section)
- `src/utils/config_simple.py` (modified -- added `"syn_flood"` to
  `DEFAULT_THRESHOLDS`)
- `docs/AUDIT_PROGRESS.md` (this section, updated)
- `docs/NEXT_AGENT_PROMPT.md` (updated -- see below)

No other files were modified. No files were deleted.

---

## STEP 5 — UDP flood + reflection-like detection (docs/NEXT_AGENT_PROMPT.md item 4)

**Sandbox limitation, re-confirmed again:** same as every prior pass --
no `nfstream`/`scapy`/`pytest` installable. All verification is
dependency-free scripts + `py_compile` + import checks + manual wiring
sanity check. **Not verified with a real `pytest` run.**

**Re-verification of prior passes' work, done first:** re-ran all 5
existing dependency-free test files together before writing any new
code -- 37/37 still passing.

### 4. UDP flood + reflection-like detection (Sections 8-9) — DONE

**New file:** `src/detectors/udp_flood.py` -- `UDPFloodDetector` /
`UDPFloodResult`, producing two distinct `threat_type` values from one
detector class (`"UDP_FLOOD"` and `"UDP_REFLECTION_LIKE"`).

**UDP_FLOOD** — same two-level, >=2-factor-combination structure as
`syn_flood.py` (deliberately copied, not reinvented):
- Aggregate level: UDP packets/sec (via `window_rates.calculate_window_rates`,
  reused directly) + destination-port concentration + destination-IP
  concentration.
- Per-destination level: UDP packets/sec + `one_packet_source_ratio`
  (NOT `source_entropy` -- same reasoning as
  `syn_flood.py::_per_destination_spoofing_evidence`, referenced rather
  than re-derived) + destination-port concentration within that group.
- Requires >=2 of the 3 possible factors at each level. A high UDP rate
  alone is just a busy legitimate service (DNS resolver, NTP pool
  member, game server). `test_udp_heavy_legitimate_workload_not_flagged`
  exercises this directly (400 flows, high aggregate rate, spread
  across 30 destinations/ports -- correctly NOT flagged).

**UDP_REFLECTION_LIKE** — grouped by `(destination_ip, destination_port)`
(i.e. by "the service being queried"), looking for reply-bytes >>
request-bytes asymmetry (`src2dst_bytes` vs `dst2src_bytes`, both
already present on `FlowRecord` -- no new fields needed). Three
possible factors, same >=2-of-N discipline: amplification ratio above
threshold, destination port in a small `REFLECTION_PRONE_PORTS` set
(DNS/NTP/SSDP/CLDAP/memcached/CharGEN/QOTD/SNMP -- documented as weak,
corroborating-only evidence, never decisive alone), and enough distinct
query sources. A minimum absolute `reply_bytes` floor (default 5000)
excludes trivially small exchanges regardless of ratio --
`test_reflection_min_reply_bytes_floor` and
`test_single_legitimate_large_response_not_flagged` both cover this.
Division-by-zero on `request_bytes == 0` is handled by reporting
`amplification_ratio: None` (insufficient data), never a fabricated
"infinite" ratio --
`test_zero_request_bytes_does_not_crash_and_reports_none_ratio` covers
this directly.

**Explicitly labeled `_LIKE`, never asserted as certain**, per item 4's
own instruction. The module docstring explains WHY this can only ever
be a shape-based inference from a single passive vantage point (can't
verify request spoofing, can't know if this volume is anomalous for the
specific service) -- and every `UDP_REFLECTION_LIKE` result's `details`
carries an explicit `"caveat"` string restating this, so it survives
past this docstring into whatever consumes the alert later.

**No bugs found this pass requiring a fix-and-retest cycle** (unlike
STEP 4's SYN-flood pass, which caught two real bugs). All 10 new tests
in `tests/test_udp_flood.py` passed on the first real run. Recorded
here for the same reason STEP 4's bugs were recorded: honesty about
what actually happened during verification.

**New test file:** `tests/test_udp_flood.py` -- 10/10 passing,
dependency-free. Covers: normal low-rate well-distributed UDP traffic
(no detection), a real UDP flood (detected), a UDP-heavy-but-legitimate
workload (single factor insufficient), reflection-like traffic on a
DNS port with enough distinct sources (detected), a single legitimate
large response below the minimum-flows floor (not detected), a high
ratio from a single source on a non-reflection port (single factor
insufficient), a trivially small absolute-volume exchange (excluded by
the min-reply-bytes floor), a zero-request-bytes edge case (no crash,
ratio reported as `None`), non-UDP flow filtering, and the statistics
helper's empty/non-UDP-input handling.

**Wired into `detector_factory.py`:** new `DetectorType.UDP_FLOOD`,
registered in `DetectorFactory.__init__`'s `self.detectors` dict
alongside `SYN_FLOOD`, and `UDPFloodDetector.get_udp_statistics` added
to `get_detector_statistics`. Same rationale as STEP 4's SYN-flood
wiring: an unregistered detector never actually runs via
`run_all_detectors`, which would violate the "must never merely LOOK
implemented" principle.

**Config additions:** `udp_flood:` section added to
`config/thresholds.yaml` (validated with `yaml.safe_load` after editing
-- confirmed still parses) and the `"udp_flood"` key added to
`DEFAULT_THRESHOLDS` in `src/utils/config_simple.py`, matching the
`syn_flood`/`ddos`/`port_scan` pattern.

**Verification performed:**
- Full `py_compile` sweep of `src/`, `scripts/`, `dashboard/`,
  `models/`, `tests/` (including `detector_factory.py`,
  `config_simple.py`) -- no syntax errors.
- `config/thresholds.yaml` re-validated with `yaml.safe_load` -- still
  parses.
- Import-check on `src.detectors.udp_flood` standalone, then on
  `src.detectors.detector_factory`.
- Re-ran ALL SIX dependency-free test files together -- 47/47 passing,
  no regressions from any prior pass's work.
- End-to-end sanity check (manual, recorded here): instantiated
  `DetectorFactory`, confirmed both `SYN_FLOOD` and `UDP_FLOOD` appear
  in `self.detectors`, ran `run_all_detectors()` and
  `get_detector_statistics()` on a small synthetic UDP-flow list --
  both `"syn_flood"` and `"udp_flood"` keys present with no errors from
  either detector. (A pre-existing, unrelated `AttributeError` from
  `dga.py` on this same synthetic flow list was observed and is NOT a
  regression from this pass -- `dga.py` expects a `timestamp` attribute
  that real `FlowRecord` objects have but this quick ad-hoc stub
  didn't; `run_detector`'s existing try/except caught it gracefully,
  exactly as designed, without affecting `syn_flood` or `udp_flood`'s
  results.)
- Grepped the whole repo for `UDPFloodDetector`/`UDPFloodResult`/
  `DetectorType.UDP_FLOOD` after the change -- only appear in
  `src/detectors/udp_flood.py`, `src/detectors/detector_factory.py`,
  and `tests/test_udp_flood.py`, as expected.

**NOT covered by this pass:**
- A real `pytest` run -- same sandbox limitation as every prior pass.
- Item 5 (evidence fusion / confidence model rebuild) -- not started.
  Both `syn_flood.py` and `udp_flood.py` now use the same flat-but-gated
  (`>=2 factors`) pattern; when item 5 lands, both should be
  reconsidered for migration onto whatever shared evidence-fusion model
  it introduces.
- Item 6 (streaming/windowing) -- still not built.
- Item 7's remaining piece (0-byte placeholders, empty demo PCAPs) --
  still open, not touched this pass.
- Item 8 (alert schema rebuild) -- still deferred; `UDPFloodResult` was
  deliberately given the same shape as `SynFloodResult`/`DDoSResult`.
- `REFLECTION_PRONE_PORTS` is a fixed, hardcoded Python constant, not
  configurable via `thresholds.yaml` -- left that way since it's
  descriptive/categorical data, not a tunable numeric threshold.

### Files changed in this pass

- `src/detectors/udp_flood.py` (new)
- `tests/test_udp_flood.py` (new)
- `src/detectors/detector_factory.py` (modified -- registered
  `DetectorType.UDP_FLOOD` / `UDPFloodDetector`)
- `config/thresholds.yaml` (modified -- added `udp_flood:` section)
- `src/utils/config_simple.py` (modified -- added `"udp_flood"` to
  `DEFAULT_THRESHOLDS`)
- `docs/AUDIT_PROGRESS.md` (this section, updated)
- `docs/NEXT_AGENT_PROMPT.md` (updated -- see below)

No other files were modified. No files were deleted.

---

## STEP 6 — Bug-hunting pass outside the item 1-4 backlog (legacy feature modules)

Not tied to a specific NEXT_AGENT_PROMPT.md item -- this was a direct
request to keep auditing/fixing bugs. Focused on `src/features/rate.py`
and `src/features/entropy.py`, the two legacy pre-audit feature modules
`network_features.py` depends on (used for ML feature extraction --
`isolation_forest.py`/`random_forest.py` consume its output), since
these hadn't been touched by STEPs 1-5 and have NO working test
coverage in this sandbox (`tests/test_features.py` imports `scapy` at
module level, so it can't even be collected here, let alone run).

**Sandbox limitation, re-confirmed again:** same as every prior pass.
All verification below is dependency-free scripts + `py_compile` +
import checks. **Not verified with a real `pytest` run.**

### Bug 1 (real, reproduced, ~30x impact): `FlowRateCalculator.get_aggregate_rates()` end_time bug

**File:** `src/features/rate.py`

`end_time` was read from `sorted_flows[-1].bidirectional_last_seen_ms`
-- the LAST element of the FULL, ever-growing `self.flows` list -- not
from `window_flows` (the flows actually being aggregated below it).
`self.flows` is append-only and never trimmed;
`NetworkFeatureExtractor.extract_flow_features()` calls
`self.rate_calculator.add_flow(flow)` on every single flow it processes
and then immediately calls `get_aggregate_rates()`, so after the first
window's worth of traffic, `self.flows` routinely contains flows far
outside any requested window. Using such a flow's `last_seen_ms` as
`end_time` inflated `actual_duration` toward (or past) the
`window_seconds` cap regardless of how tightly clustered the actual
in-window flows were, silently DIVIDING BY TOO LARGE A DENOMINATOR and
under-reporting every rate feature.

**Reproduced concretely** (see `tests/test_rate_calculator.py::test_aggregate_rates_not_diluted_by_out_of_window_flows`):
100 flows tightly packed into ~1 real second, plus a single unrelated
flow from 600 seconds later still sitting in `self.flows`, reported
**16.7 packets/sec instead of the correct ~1005 packets/sec -- a ~30x
underestimate** -- purely because of that one out-of-window flow's
presence in the list.

**Fix:** compute `end_time = max(f.bidirectional_last_seen_ms for f in window_flows)`
AFTER filtering to `window_flows`, not before, from the full list.

**Also documented, not fixed as a drive-by:** a deeper design issue in
the same class -- `self.flows` is never trimmed, and
`get_source_destination_ratio()`/`get_unique_ips_count()` intentionally
rely on that full history, so simply trimming the list would silently
change THEIR behavior too. This means `get_aggregate_rates()`'s
`start_time` stays anchored to the very first flow this instance ever
saw for the lifetime of the process, so it increasingly reports "rate
over the first window_seconds after startup" rather than a true rolling
rate as a long capture session progresses. This needs the real
streaming/windowing mechanism (NEXT_AGENT_PROMPT.md item 6) to fix
properly -- added a class-docstring note pointing future agents at it
rather than a scope-creeping partial fix here.

### Bug 2 (real, latent, not yet reachable): `DomainEntropyAnalyzer.calculate_ngram_features()` inconsistent return shape

**File:** `src/features/entropy.py`

The early-return branches (`not text`, and `not ngrams` -- i.e. input
shorter than the n-gram size, a realistic case for short DGA-style main
labels) returned `{"ngram_score": 0.0, "unique_ngrams": 0}`, omitting
the `"ngram_entropy"` key that the normal-path return always includes.
Grepped every consumer of this output in the repo
(`grep -rn "ngram_entropy"`) -- currently nothing does unguarded
`features["ngram_entropy"]` access (`dga.py` only reads `"ngram_score"`,
via `.get(..., 1.0)`), so this was NOT causing a crash today. Still a
real latent bug: any future caller reading `ngram_entropy` directly
would `KeyError` on exactly the short-domain-label inputs a DGA
detector is most likely to see. Fixed by making both early-return
branches include `"ngram_entropy": 0.0`, so the function always returns
the same set of keys.

**New test files:**
- `tests/test_rate_calculator.py` -- 5/5 passing. Covers: empty
  calculator, the out-of-window-dilution regression (the main bug,
  reproducing the exact ~30x-underestimate scenario), an all-flows-
  within-window sanity check, a single zero-duration flow (no
  divide-by-zero), and confirmation that
  `get_source_destination_ratio()`/`get_unique_ips_count()` are
  unaffected by the fix (they intentionally use full history).
- `tests/test_entropy.py` -- 6/6 passing. Covers: Shannon entropy on
  empty/uniform/max-entropy inputs, `normalized_entropy` staying within
  [0, 1] across varied inputs, the `calculate_ngram_features` dict-shape
  regression test (empty / shorter-than-n / normal-length inputs all
  returning the same key set), `analyze_domain` on a short main label
  (the actual reachable path that hit the shape inconsistency) and on
  empty input, and digit/vowel/consonant ratio correctness.

**Verification performed:**
- Full `py_compile` sweep of `src/`, `scripts/`, `dashboard/`,
  `models/`, `tests/` -- no syntax errors.
- Import-checks on both touched modules.
- Reproduced Bug 1 concretely with a standalone repro script BEFORE
  fixing (recorded above), then re-ran the same repro AFTER fixing to
  confirm the corrected magnitude (~1005 pkts/sec, matching the real
  ~1-second span of the in-window flows).
- Grepped the whole repo for `ngram_entropy` usage before "fixing" Bug
  2, to correctly characterize it as latent/not-yet-reachable rather
  than overstating it as an active crash.
- Re-ran ALL EIGHT dependency-free test files together
  (`test_window_rates.py`, `test_source_stats.py`,
  `test_scan_failure_signatures.py`, `test_spoofing_likelihood.py`,
  `test_syn_flood.py`, `test_udp_flood.py`, `test_rate_calculator.py`,
  `test_entropy.py`) -- 58/58 passing, no regressions from any prior
  pass's work.

**NOT covered by this pass:**
- A real `pytest` run of `tests/test_features.py` (or any pytest-based
  file) -- same sandbox limitation as every prior pass. Someone with
  scapy/nfstream/pytest installed should specifically re-run
  `tests/test_features.py` given this pass touched two of the modules
  it imports.
- The deeper `FlowRateCalculator` windowing/anchoring design issue
  described above -- documented, not fixed; belongs with item 6.
- Did not do a full line-by-line audit of every remaining untouched
  module this pass (`risk_score.py`, `alert_engine.py`,
  `flow_analyzer.py`, `pcap_reader.py`, `network_features.py` itself
  beyond its use of `rate.py`, the ML model files, `cti/`,
  `blockchain/`, `storage/`, `ingest/`) -- scoped this pass to the two
  modules most clearly reachable and least-audited (no test coverage at
  all in this sandbox) rather than attempting everything at once.

### Files changed in this pass

- `src/features/rate.py` (modified -- fixed the `end_time` bug, added a
  class-docstring note about the deeper windowing/anchoring issue)
- `src/features/entropy.py` (modified -- fixed the inconsistent
  `calculate_ngram_features` return shape)
- `tests/test_rate_calculator.py` (new)
- `tests/test_entropy.py` (new)
- `docs/AUDIT_PROGRESS.md` (this section, updated)

No other files were modified. No files were deleted.

---

## STEP 7 — NEXT_AGENT_PROMPT.md item 7: remaining 0-byte placeholders

The two quick wins in item 7 (`tests/confest.py` -> `conftest.py` rename,
dead `elif` in `scan.py`) were already DONE per the record above. This
pass closes the rest: `docker/Dockerfile`, `docker/docker-compose.yml`,
`docs/ARCHITECTURE.md`, `docs/THREAT-MODELS.md`, `setup.py`,
`requirements-lock.txt`, and the 3 still-empty demo pcaps
(`demo/ddos.pcap`, `demo/dga.pcap`, `demo/normal.pcap` -- only
`demo/port_scan.pcap` had content before this pass, and even that was
just a valid-but-empty 24-byte pcap global header with zero packets).

**Sandbox limitation, unchanged from every prior pass:** still no
network access (`pip install` fails, no `docker build` possible here)
and no `scapy` installed. This shaped several of the choices below --
each is called out explicitly rather than silently working around the
limitation.

### `setup.py`

Standard `setuptools` setup filled in: reads `requirements.txt` for
`install_requires` (so the dependency list has exactly one source of
truth), `find_packages(include=["src", "src.*"])` for package
discovery, a `dev` extra for pytest, and two console-script entry
points (`cyber-detecter-pipeline`, `cyber-detecter-dashboard`) pointing
at `scripts/run_pipeline.main` and `scripts/run_dashboard.main`, which
both already exist and take no required arguments. Verified `python3
-m py_compile setup.py` passes and `setuptools.find_packages(...)`
with the same include pattern returns all 13 `src.*` subpackages and no
unexpected extras (`models/` and `tests/` are correctly excluded --
`models/` at the repo root duplicates `src/models/` and is a separate,
pre-existing concern not part of this item). **Not verified:** an
actual `pip install -e .` (needs network access this sandbox doesn't
have).

### `requirements-lock.txt`

Deliberately written with an explicit provenance header stating it was
NOT produced by `pip freeze` in a provisioned environment (impossible
here -- no network access) -- it's the `requirements.txt` lower bounds
pinned with `==` as a best-effort placeholder, with a TODO telling the
next agent/engineer with network access exactly how to regenerate it
for real. Chose this over leaving it empty or fabricating plausible-
looking-but-invented exact versions, either of which would violate the
"must never merely LOOK implemented" principle from the original brief
-- an empty file silently implies "no pins needed" and fabricated
versions silently imply "this was actually resolved," both false.

### `docker/Dockerfile` and `docker/docker-compose.yml`

Standard `python:3.11-slim`-based image: installs `libpcap-dev` (needed
for scapy's capture bindings), `tcpdump`, and `build-essential`
(several of the pinned ML/data deps still need to compile from source
on slim images), installs `requirements.txt` then the package itself
(`pip install -e .`), runs as a non-root user, and defaults to running
the batch pipeline against the bundled `demo/port_scan.pcap`.
`docker-compose.yml` defines a `dashboard` service (Streamlit, port
8501) and a `pipeline` service (one-shot batch run), both passing
through the optional CTI API key env vars from `env.example`. A third
`live-capture` service is included **commented out**, requiring
`network_mode: host` and `cap_add: [NET_ADMIN, NET_RAW]` explicitly --
kept opt-in rather than default, consistent with
`src/ingest/live_capture.py`'s own "controlled lab environments with
permission" warning and the project's passive-only design constraint.

**Verified:** `docker-compose.yml` parses as valid YAML
(`yaml.safe_load`) and both services' `image`/`build`/`command` keys
resolve as expected. **NOT verified:** an actual `docker build` or
`docker compose up` -- this sandbox has neither Docker nor network
access to pull the base image or install packages. Flagging explicitly
per this document's own rule against claiming untested things as
tested.

### `docs/ARCHITECTURE.md` and `docs/THREAT-MODELS.md`

Written directly from the current state of `src/` (detector docstrings,
module structure, the STEP 1-6 history in this document, and the "what's
left" section of `docs/NEXT_AGENT_PROMPT.md`) rather than from the
original brief in isolation, so they describe what actually exists
today -- including explicitly documenting the streaming/windowing gap,
the ML-not-wired-in status, and per-detector "what it does NOT claim"
caveats (spoofing evidence vs. proof, UDP_REFLECTION_LIKE's inherent
single-vantage-point limitation, the hash chain being an integrity
mechanism and not a correctness guarantee). No new claims about system
capability were introduced beyond what the code and prior audit
sections already establish.

### Demo pcaps (`demo/ddos.pcap`, `demo/dga.pcap`, `demo/normal.pcap`)

`scripts/generate_test_data.py` (the existing generator) imports
`scapy.all`, which is not installed here, so it could not be run to
produce these. Rather than leave them at 0 bytes or fabricate non-pcap
placeholder content, wrote a new, separate,
**dependency-free** generator, `scripts/generate_test_data_stdlib.py`
(stdlib `struct`/`socket`/`random` only -- no scapy, no network),
that hand-assembles classic-format pcap files (matching the exact
global-header format already present in `demo/port_scan.pcap`) with
real Ethernet/IP/TCP/UDP/ICMP framing and correct IP/TCP/UDP/ICMP
checksums:

- `normal.pcap` -- 122 packets, mixed HTTP/HTTPS handshakes and
  ordinary DNS lookups across a few clients/servers; a low/no-alert
  baseline.
- `ddos.pcap` -- 1,500 SYN packets from 60 distinct spoofed-looking
  source /24s at one victim IP:port in a tight time window --
  intended to exercise `ddos.py` and `syn_flood.py`.
- `dga.pcap` -- 50 DNS queries, mostly long high-entropy
  consonant/vowel-alternating labels with a few ordinary lookups mixed
  in -- intended to exercise `dga.py` and `entropy.py`.

This is explicitly documented in the new script's own docstring as a
**fallback**, not a replacement for `generate_test_data.py` -- it
covers fewer protocol variations and doesn't use Scapy's randomization
helpers. Prefer the original script on any machine with scapy
installed.

**Verified:** wrote a second, independent, stdlib-only pcap *parser*
(not reusing any code from the generator) and confirmed all three
files parse as structurally valid classic-pcap with the expected
packet counts, and that a byte-level sample of parsed packets shows
correct EtherType, IP protocol number, and source/destination
addresses matching what each scenario intended (e.g. `ddos.pcap`'s
first packets are TCP from `198.51.x.x` sources to `10.0.0.1`;
`dga.pcap`'s first packets are UDP DNS queries from
`192.168.1.150` to `8.8.8.8`). **NOT verified:** these files have NOT
been run through the real `src/ingest/pcap_reader.py` (which needs
scapy's `rdpcap`) or `src/flow/nfstream_wrapper.py`/detectors end to
end -- that needs a machine with scapy (and ideally nfstream)
installed. The structural-validity check above confirms the files are
well-formed pcap, not that the full detection pipeline actually raises
the intended alerts on them.

### Verification summary for this pass

- Full `py_compile` sweep of `src/`, `scripts/`, `dashboard/`, `models/`
  -- no syntax errors, including the two new files
  (`setup.py`, `scripts/generate_test_data_stdlib.py`).
- Re-ran all 8 existing dependency-free test files
  (`test_window_rates.py`, `test_source_stats.py`,
  `test_scan_failure_signatures.py`, `test_spoofing_likelihood.py`,
  `test_syn_flood.py`, `test_udp_flood.py`, `test_rate_calculator.py`,
  `test_entropy.py`) -- 58/58 passing, no regressions (this pass
  touched no detector/feature code, only docs/packaging/demo-data, so
  this is a sanity check rather than a targeted regression test).
- Grepped the repo for existing references to the files touched in
  this pass before editing them -- none found beyond their own mentions
  in `docs/AUDIT_PROGRESS.md`/`docs/NEXT_AGENT_PROMPT.md` (i.e. nothing
  else in the codebase was importing/depending on the previously-empty
  files' contents, so filling them in carried no risk of breaking an
  existing consumer).
- `docker-compose.yml` validated as parseable YAML via `yaml.safe_load`.
- New demo pcaps validated by an independent stdlib pcap parser (byte
  offsets/counts/addresses match intent) -- NOT by the real
  scapy-based `pcap_reader.py` or by running them through
  `scripts/run_pipeline.py`, which needs scapy/nfstream installed.

**NOT covered by this pass, needs a fully-provisioned machine:**
- `docker build` / `docker compose up` of the new Docker assets.
- `pip install -e .` of the new `setup.py`.
- Running `demo/ddos.pcap`, `demo/dga.pcap`, `demo/normal.pcap` through
  the actual pipeline (`scripts/run_pipeline.py`) to confirm each
  scenario trips the detector it was designed to exercise, and that
  `normal.pcap` does NOT trip any detector.
- Regenerating `requirements-lock.txt` for real via `pip freeze`.

### Files changed in this pass

- `setup.py` (filled in, was 0 bytes)
- `requirements-lock.txt` (filled in, was 0 bytes)
- `docker/Dockerfile` (filled in, was 0 bytes)
- `docker/docker-compose.yml` (filled in, was 0 bytes)
- `docs/ARCHITECTURE.md` (filled in, was 0 bytes)
- `docs/THREAT-MODELS.md` (filled in, was 0 bytes)
- `scripts/generate_test_data_stdlib.py` (new)
- `demo/ddos.pcap`, `demo/dga.pcap`, `demo/normal.pcap` (generated,
  were 0 bytes)
- `docs/AUDIT_PROGRESS.md` (this section, updated)
- `docs/NEXT_AGENT_PROMPT.md` (updated -- see below)

No other files were modified. No files were deleted.

---

## STEP 8 — Item 5 (evidence fusion in `src/detectors/ddos.py`)

**Bug found and fixed (false positive):** `_analyze_aggregate_traffic`
used to flag ordinary single-client, single-destination traffic (e.g.
one user browsing one website) as a potential DDoS. Root cause:
`calculate_concentration()` returns a hardcoded `1.0` whenever only one
distinct category is present (documented in its own docstring as a
degenerate case, not "high concentration among a real population").
With only one source and one destination, both `source_concentration`
and `destination_concentration` were trivially `1.0` and, under the old
flat `confidence_factors` scheme, either alone was enough to flag
`flood_detected = True`. Fixed by requiring a minimum population
(`MIN_DISTINCT_FOR_CONCENTRATION_EVIDENCE = 5`, matching the existing
`spoofing_likelihood.py` `MIN_SOURCES_FOR_SCORE = 5` convention) before
either concentration figure counts as evidence at all.

**Evidence fusion rewrite:** replaced the flat `confidence_factors`
list with named evidence components (`volumetric`, `byte_rate`,
`tcp_syn`, `source_concentration`, `destination_concentration`, and a
new `asymmetry` component from `_calculate_directional_asymmetry` --
one-way traffic with little/no reply, typical of a spoofed flood that
never completes a handshake). Same >=2-factor-combination discipline
as `syn_flood.py`/`udp_flood.py`: no single weak signal decides alone.
Added `rule_score`/`ml_probability` fields to `DDoSResult` (same
pattern as those two detectors); `ml_probability` stays `None`, never
fabricated as `0.0`, since no ML model is wired into DDoS decisions.
Applied the same evidence-component treatment (minus destination
concentration, which isn't meaningful once already filtered to one
destination) to `_analyze_destination_flows`, replacing its old
`min(0.8, pps / threshold*2)` ad-hoc formula.

**Compatibility fix caught during self-review:** initially stored the
new evidence under `details["evidence_components"]`. Before finishing,
grepped for existing consumers and found `src/alerts/alert_engine.py`'s
`_detection_to_alert()` generically reads `details["evidence"]` (flat
name->value) into `Alert.evidence` for the dashboard -- the same key
name `syn_flood.py`/`udp_flood.py` already use. Renaming it would have
silently emptied `Alert.evidence` for every DDoS alert without an
error anywhere. Fixed to keep `details["evidence"]` flat and
alert_engine-compatible, with the per-component weights in a separate
`details["evidence_weights"]` for anyone who wants the fuller trail.

**Verification:** this sandbox still has no network access, but
`FlowRecord` (`src/flow/nfstream_wrapper.py`) and `DDoSDetector`
(`src/detectors/ddos.py`) both import cleanly without scapy/nfstream
(nfstream is optional/lazy; scapy is only needed by the PCAP-reading
path), so this pass could test the REAL classes directly instead of a
FakeFlow stand-in:
- New `tests/test_ddos_evidence_fusion.py`, 7/7 passing: the false-
  positive regression case, named-evidence-component detection, the
  rule_score/confidence/ml_probability separation, the >=2-factor
  gate, directional asymmetry (including the "no request traffic at
  all" degenerate case staying `None`, not `0.0`/`1.0`), and an
  explicit guard test on the `details["evidence"]` key shape.
- Full `py_compile` sweep of `src/`, `scripts/`, `dashboard/`,
  `models/` -- no errors.
- Re-ran all 8 pre-existing dependency-free test files -- 58/58
  passing, no regressions.
- Live integration check (not part of the formal test file, run ad
  hoc): fed real `DDoSDetector` output through the real `AlertEngine`
  end-to-end and confirmed `Alert.evidence`/`confidence`/`severity`
  populate correctly.

**NOT covered by this pass, still needs a fully-provisioned machine:**
the existing `tests/test_detectors.py::TestDDoSDetector` (uses scapy at
import time, can't run here) -- reasoned through its two DDoS-related
cases by hand instead (`create_ddos_flows` has enough distinct evidence
components to still detect; `create_normal_flows` is the exact false-
positive shape this pass fixed) but this should be re-run for real on a
machine with scapy/pytest installed to confirm.

### Files changed in this pass
- `src/detectors/ddos.py` (evidence-fusion rewrite, concentration
  false-positive fix, new `_calculate_directional_asymmetry` helper,
  `rule_score`/`ml_probability` fields)
- `tests/test_ddos_evidence_fusion.py` (new)
- `docs/AUDIT_PROGRESS.md` (this section)

No other files were modified. No files were deleted.

### What's left (unchanged from `docs/NEXT_AGENT_PROMPT.md`)
Item 5 is now DONE. Items 6 (streaming/windowing) and 8 (alert schema
rebuild) are still open -- see `docs/NEXT_AGENT_PROMPT.md` for the
detailed brief on each.


## Phase F — streaming/windowing (2026-08-30)

Implemented the previously missing Section 5 streaming/windowing foundation.

- Added `src/streaming/windowing.py` with event-time `SlidingWindow` and
  `WindowAggregator`.
- Uses `deque` and expires flows older than the configured observation
  horizon, keeping active memory bounded by the window rather than the
  lifetime of the process.
- Default window/slide are 10s/1s and are configurable.
- Window assignment uses flow traffic timestamps (`bidirectional_first_seen_ms`
  first, then documented fallbacks); processing speed does not affect windows.
- Missing timestamps are tracked separately rather than fabricated into a
  traffic-time boundary.
- Added source churn between consecutive windows using symmetric difference
  over union. The first window explicitly reports `None` with
  `no_previous_window`.
- Added `ThreatDetectionPipeline.process_flow_stream()` as the incremental
  window boundary; callers can receive each due window through `on_window`.
  Existing batch and live paths remain backward compatible.
- Added dependency-free regression tests in `tests/test_streaming_windowing.py`.

Scapy installation was attempted before Phase F, but this sandbox has no
network/package-index access, so `pip install scapy` failed with DNS
resolution errors. The Phase F implementation itself is stdlib-only.

---

## Documentation catch-up (2026-08-30)

This document had fallen behind the actual repo state. A fresh audit of
`cyber_detecter_complete_repaired.zip` (uploaded after Phase F, above)
found undocumented work already present and passing: `src/flow_normalization.py`
(canonical flow contract, Section 4), `src/risk/evidence_types.py` +
`src/risk/authoritative_risk.py` (the single authoritative risk engine,
Sections 24-26, bounded/reproducible), `Alert` in `src/alerts/alert_models.py`
already carrying the full Section-28 field set, config-driven detector
enabling, and a bounded incremental flow aggregator. Whoever did that work
did not update this file or `NEXT_AGENT_PROMPT.md` — a reminder that this
doc is only useful if kept current. Verified via a hand-rolled pytest-stub
collector (`raises`/`importorskip` only, not real pytest) against
`tests/test_flow_normalization_phase_a.py`, `tests/test_evidence_types_phase_c.py`,
`tests/test_authoritative_risk_phase_c.py`, `tests/test_phase_bc_integration_guards.py`,
`tests/test_final_repair_guards.py` — 17/17 passing, on top of the
previously-known 65/65 dependency-free tests (82/82 total before this
pass's own additions).

## STEP 9 — CTI rate-limiting (Section 27)

**Gap found:** `src/cti/enrichment.py` had result caching (1-hour TTL) but
no rate limit on external lookups. A flood of distinct indicators (e.g.
many spoofed source IPs, each a cache miss) could still force unlimited
external CTI calls.

**Fix:** new `src/cti/rate_limiter.py` -- `CTIRateLimiter`, a plain
stdlib sliding-window counter (deque of timestamps, no dependencies).
Wired into `ThreatIntelligenceEnricher`:
- `lookup_indicator_with_status()` (new) returns `(result, status)` where
  `status` is `"cache_hit"` / `"checked"` / `"rate_limited"` -- added
  specifically so a rate-limit skip is never indistinguishable from a
  real "checked, not malicious" result (Section 35: a degraded subsystem
  must never read as "no threat"). `lookup_indicator()` (existing
  signature) is kept as a thin wrapper for backward compatibility with
  `tests/test_cti.py` and `scripts/test_cti.py`.
- Cache hits do NOT consume rate-limit budget (no external call is made).
- A rate-limited lookup is explicitly NOT cached as a negative result --
  once budget frees up it gets checked for real, not served a stale
  "clean" verdict.
- `enrich_alert()` now records `alert.details['cti_rate_limited']` /
  `['cti_rate_limited_indicators']` when any of an alert's indicators
  were skipped, so this is visible on the alert itself, not just in logs.
- `get_provider_status()` now includes a `_rate_limiter` health block
  (allowed/rejected counts, current load) -- Section 35 system health.
- Config-driven (Section 37): new `cti:` section in
  `config/thresholds.yaml` (`max_lookups_per_window: 60`,
  `rate_limit_window_seconds: 60.0`) and matching `"cti"` entry in
  `DEFAULT_THRESHOLDS` (`src/utils/config_simple.py`). `src/streaming/pipeline.py`
  now reads these via `config_manager.get_threshold("cti", ...)` (same
  pattern as `syn_flood.py`/`udp_flood.py`'s `_load_thresholds()`), with
  the pipeline's own `config` dict override taking priority so existing
  callers passing `config={}` are unaffected.

**New test file:** `tests/test_cti_rate_limiting.py` -- 8/8 passing,
dependency-free (`python3 tests/test_cti_rate_limiting.py`). Covers: cap
enforcement, sliding-window expiry, invalid-config rejection, real
allowed/rejected counters, cache hits not consuming budget, a
rate-limited lookup being distinguishable from a real negative AND not
falsely cached, `enrich_alert()` exposing rate-limited indicators
explicitly, and rate-limiter health appearing in `get_provider_status()`.
Note: `requests` happens to be importable in this sandbox (unlike
scapy/nfstream/sqlalchemy/pytest), so `src.cti.enrichment` and
`src.cti.providers` could be exercised directly for real, not via stubs.

**Verification performed:**
- `python3 -m py_compile` on all touched files, clean.
- Re-ran all previously-passing dependency-free suites plus the new one
  -- 90/90 passing (82 prior + 8 new), no regressions.
- Grepped the whole repo for `lookup_indicator`/`ThreatIntelligenceEnricher(`
  usage before finishing -- `scripts/test_cti.py`, `scripts/final_verification.py`,
  and `tests/test_cti.py` all construct the enricher with defaults or
  call `lookup_indicator()` (not the new `_with_status` variant), both
  of which keep working unchanged.
- `src.streaming.pipeline` still fails to import here, but ONLY on the
  same pre-existing `ModuleNotFoundError: No module named 'sqlalchemy'`
  present before this pass (confirmed unrelated) -- verified the CTI
  config wiring itself directly via `config_manager.get_threshold('cti', ...)`
  since the full pipeline import can't be exercised in this sandbox.
- `config/thresholds.yaml` re-validated with `yaml.safe_load` after the
  edit -- still parses, `cti` section present.

**NOT covered by this pass:**
- A real `pytest` run of `tests/test_cti.py` -- same sandbox limitation
  as ever, though this file's assertions were reasoned through by hand
  against the (unchanged) `lookup_indicator()` signature.
- End-to-end `ThreatDetectionPipeline` construction (blocked by the
  pre-existing missing `sqlalchemy`, not by this pass's changes).
- Dashboard authentication (Section 36) and database `schema_version`
  (Section 39) -- both still open, flagged in the prior audit pass, not
  touched here; user was asked which to prioritize next and had no
  preference, so this pass picked CTI rate-limiting as the most
  security-relevant of the three (unbounded external calls from
  attacker-controlled traffic).

### Files changed in this pass
- `src/cti/rate_limiter.py` (new)
- `src/cti/enrichment.py` (modified -- rate limiter wiring, new
  `lookup_indicator_with_status()`, `cti_rate_limited*` alert fields,
  `_rate_limiter` in `get_provider_status()`)
- `src/streaming/pipeline.py` (modified -- config-driven CTI rate-limit
  construction)
- `config/thresholds.yaml` (modified -- added `cti:` section)
- `src/utils/config_simple.py` (modified -- added `"cti"` to
  `DEFAULT_THRESHOLDS`)
- `tests/test_cti_rate_limiting.py` (new)
- `docs/AUDIT_PROGRESS.md` (this section)

No other files were modified. No files were deleted.

### What's left
Dashboard authentication (Section 36) and database `schema_version`
(Section 39) remain open, plus the full Section 43-50 acceptance-
criteria sweep (full pytest run, Docker build, live-traffic test) that
has never been possible in this sandbox for lack of network access.
