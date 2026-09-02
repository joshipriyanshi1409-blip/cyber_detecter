# Handoff Prompt — CyberDetecter Audit/Repair, Continuation

Paste this whole document as your instructions to the next AI agent (or use
it as your own reference if resuming this work yourself).

---

## Context you need before touching anything

You are continuing a full repository audit/repair/hardening pass on
`cyber_detecter`, a passive/read-only AI-based cyber threat detection
prototype (DDoS, C2 beaconing, DGA/DNS tunnelling, encrypted-traffic
metadata analysis, port scanning, data exfiltration). The system is
strictly passive: no active probing, no packet injection, no blocking, no
handshake completion, no TLS/QUIC decryption.

**Before writing any code, read `docs/AUDIT_PROGRESS.md` in this repo.**
It is the ground truth for what has already been fixed and verified, what
was found-but-not-fixed, and exactly which files were touched. Do not
re-derive this from scratch — it will waste effort and risks contradicting
work already done and tested.

**Non-negotiable rules that still apply (carried over from the original
audit brief):**
- Fix root causes, not symptoms. Don't suppress exceptions into empty
  lists. Don't silently continue after detector failures.
- Never fabricate cybersecurity capabilities (no claiming guaranteed
  spoofing detection, guaranteed amplification detection, active
  blocking, etc.). Use `*_likely`, `evidence`, `confidence`, `rule_score`
  language.
- Keep `rule_score` and `ml_probability` as clearly separate fields,
  always. Never copy one into the other. If ML hasn't contributed to a
  decision, its field must be `None`/omitted, not `0`.
- Distinguish "missing/unavailable" from "zero" everywhere (see
  `src/features/window_rates.py` for the pattern already established —
  reuse it, don't reinvent it).
- Preserve extensibility for DGA/C2/TLS-QUIC/recon/exfiltration — don't
  build DDoS-specific plumbing that makes these harder to bolt on later.
- Every fix needs a real, runnable, dependency-free test where possible
  (see `tests/test_window_rates.py` for the pattern: pure Python,
  `FakeFlow` dataclass instead of needing real scapy/nfstream objects,
  runs standalone with `python3 tests/test_X.py`).
- **You likely won't have network access either.** Check first. If you
  don't, you can't install nfstream/scapy/pytest — verify what you can
  with dependency-free simulations and stubs (see `docs/AUDIT_PROGRESS.md`
  for exactly how this was done last time), and clearly flag what still
  needs verification on a properly-provisioned machine. Do not claim
  something is "tested" if it only passed against a hand-rolled stub.
  **Confirmed again in the STEP 2 pass:** no network access, `pip
  install` fails outright, and every existing `tests/test_*.py` file
  imports `pytest` (several also `scapy`) at module level, so none of
  them can even be *imported* here, let alone run — not just "run
  without pytest's fixture machinery". If this is still true for you,
  say so explicitly rather than repeating an old pass/fail claim you
  can't actually reproduce.
- Don't modify tests just to make them pass. If a test encodes wrong
  behavior, fix the implementation or replace the test with a correct one
  — and say so explicitly.
- After any schema change (new/renamed field on `FlowRecord`, `DDoSResult`,
  `Alert`, etc.), grep the WHOLE repo for the old name/usage before
  declaring the change safe. `git grep` or plain `grep -rn` across
  `src/`, `scripts/`, `dashboard/`, `tests/`, `models/`.

---

## What's already done (don't redo this)

- Flow directionality bug fixed (Scapy fallback now correctly tracks
  bidirectional traffic instead of mislabeling everything as
  `src2dst` with `dst2src` hardcoded to 0).
- ICMP support added to the Scapy fallback.
- Timestamp semantics fixed (traffic-time, not `time.time()`).
- `nfstream` import made optional/lazy — the module and the Scapy
  fallback now work without nfstream installed.
- **The core DDoS aggregate-rate bug is fixed.** `src/features/window_rates.py`
  is the new, correct, tested implementation. `src/detectors/ddos.py` uses
  it in all three places that used to duplicate the buggy
  `sum(flow.duration)` calculation.
- New `FlowRecord` fields exist but are NOT yet consumed by any detector:
  `syn_only_packets`, `syn_ack_packets`, `icmp_packets`, `icmp_bytes`,
  `icmp_type_counts`.
- **`tests/confest.py` renamed to `tests/conftest.py`** (typo fix, item 7).
- **Dead `elif` in `src/detectors/scan.py` fixed** (item 7) — now
  distinguishes SYN-with-no-response (`syn_only_count`) from
  SYN-with-RST-received (`failed_connections` only), using
  `rst_packets`, which was previously never consulted. See
  `tests/test_scan_failure_signatures.py`.
- **Item 1 (source-IP statistics module) is DONE.** New
  `src/features/source_stats.py`: `calculate_concentration(values)`
  (HHI, flow-occurrence-based), `shannon_entropy_normalized(counts)`
  (packet-volume-based, kept as a separate output from concentration —
  do not merge them), `calculate_source_packet_distribution`,
  `calculate_source_byte_distribution`, and the combining
  `calculate_source_stats(flows)` which returns unique source count,
  both distributions, top-source fraction, entropy, concentration,
  one-packet-source count/ratio, and an explicit `source_churn: None` /
  `source_churn_reason: "requires_streaming_window"` (churn needs item 6
  below — don't stub a fake single-window approximation for it).
  `tests/test_source_stats.py` has 8/8 dependency-free tests. **Use this
  module for item 2 (spoofing-likelihood) and item 3 (SYN-flood
  detector) below — don't reimplement source-diversity stats again.**
- **Deduplication:** the HHI concentration formula existed as 3 separate
  private-method copies (`ddos.py` x1, `network_features.py` x1 used
  from 4 call sites). All 3 now delegate to the shared
  `calculate_concentration` in `source_stats.py`. If you find yourself
  about to write a 4th copy of an HHI/entropy/distribution calculation
  anywhere in this repo, check `src/features/source_stats.py` and
  `src/features/window_rates.py` first — that's exactly the trap this
  cleanup was meant to close.
- **Item 2 (spoofing-likelihood evidence) is DONE.** New
  `src/features/spoofing_likelihood.py`:
  `calculate_spoofing_likelihood(flows)` returns a weighted 0-1
  `spoofing_likelihood` score (or `None`/`"insufficient_data"` below
  `MIN_SOURCES_FOR_SCORE = 5` distinct sources) plus a non-committal
  label, built from `source_entropy`, `one_packet_source_ratio`, and
  `destination_concentration` (source_churn always reported unavailable
  — needs item 6).
  `tests/test_spoofing_likelihood.py` has 7/7 dependency-free tests.
  **IMPORTANT caveat learned while building item 3 (see below): don't
  call `calculate_spoofing_likelihood` on a flow set that's already
  been filtered down to one destination.** Its `destination_concentration`
  signal is computed from the very flows you pass it — if they all
  share one destination already, that signal is trivially `1.0` every
  time and silently inflates the score. `src/detectors/syn_flood.py`'s
  `_per_destination_spoofing_evidence` is the pattern to copy for any
  future per-destination-grouped detector that wants source-diversity
  evidence — it deliberately does NOT call the full function.
- **Item 3 (SYN-flood-specific detector) is DONE.** New
  `src/detectors/syn_flood.py`: `SynFloodDetector` / `SynFloodResult`,
  the first consumer of `syn_only_packets`/`syn_ack_packets`. Two-level
  analysis (aggregate: rate + completion + destination concentration;
  per-destination: rate + completion + `one_packet_source_ratio`),
  gated on **at least 2 of 3 factors** crossing threshold — never a
  single ratio alone, per this document's own instruction below.
  Registered in `detector_factory.py` as `DetectorType.SYN_FLOOD` so it
  actually runs via `run_all_detectors`. Config defaults added to
  `config/thresholds.yaml` and `config_simple.py`.
  `tests/test_syn_flood.py` has 9/9 dependency-free tests, including a
  legitimate-but-syn-heavy-workload case that caught two real bugs
  during development (see `docs/AUDIT_PROGRESS.md` STEP 4 for the full
  story) — keep that test if you touch this detector again; it's the
  one that actually exercises the "don't decide on a single ratio"
  rule and the destination-concentration double-counting trap above.

---

## What's left — prioritized

Work in roughly this order (matches the original brief's Section 57
sequencing: correctness of DDoS core first, then breadth, then UI/docs
last).

### 1. Source-IP statistics module (original brief Section 6.3) — DONE, see above.

### 2. Spoofing-likelihood evidence (Section 6.4) — DONE, see above.

### 3. SYN-flood-specific detector (Section 7) — DONE, see above.

### 4. UDP flood + reflection-like detection (Sections 8-9) — DONE, see above.
New `src/detectors/udp_flood.py`: `UDPFloodDetector` produces both
`UDP_FLOOD` (two-level, >=2-factor, same pattern as `syn_flood.py`) and
`UDP_REFLECTION_LIKE` (grouped by destination_ip+port, amplification
ratio + reflection-prone-port + source-diversity, also gated on >=2
factors, always carries an explicit interpretive caveat in `details`).
Registered as `DetectorType.UDP_FLOOD`. `tests/test_udp_flood.py` has
10/10 passing, no bugs found this pass (unlike item 3's SYN-flood pass,
which caught two). Config defaults in `config/thresholds.yaml` /
`config_simple.py` under `udp_flood:`.

### 5. Evidence fusion + confidence model (Sections 12-13) — DONE, see STEP 8 in AUDIT_PROGRESS.md.
Replaced `ddos.py`'s flat `confidence_factors.append(...)` list with
explicit named evidence components (volumetric, byte rate, TCP/SYN,
source-diversity, destination-concentration, asymmetry), each gated on
a minimum population before concentration counts as evidence (this
caught and fixed a real false-positive bug on ordinary single-source/
single-destination traffic). `rule_score` is now a proper field,
separate from `ml_probability` (always `None` -- no ML model is wired
into DDoS decisions yet). `details["evidence"]` stays a flat dict,
matching `syn_flood.py`/`udp_flood.py` and what `alert_engine.py`
generically extracts into `Alert.evidence`; weights are in the new
`details["evidence_weights"]`. New `tests/test_ddos_evidence_fusion.py`,
7/7 passing against the real `DDoSDetector` class.

### 6. Streaming/windowing mechanism (Section 5) — architecturally important
Nothing like this exists yet (`src/streaming/pipeline.py` is batch-only:
whole-PCAP-in-memory or live-capture-only). This blocks real "source
churn across windows" and real incremental/bounded-memory processing.
Recommend a new `src/streaming/windowing.py` with a `SlidingWindow` /
`WindowAggregator` class using a `deque`, default 10s window,
configurable slide interval, expiring old flows out of bounded memory.
This is a substantial, self-contained piece of work — don't try to do it
as a drive-by inside another fix.

### 7. Small, low-risk fixes (quick wins) — DONE, see STEP 7 in AUDIT_PROGRESS.md
- ~~Rename `tests/confest.py` → `tests/conftest.py`~~ DONE.
- ~~Fix the dead `elif` branch in `src/detectors/scan.py`~~ DONE (used
  `rst_packets` to distinguish silent-drop from RST-refused, as
  predicted).
- ~~`docker/Dockerfile`, `docker/docker-compose.yml`,
  `docs/ARCHITECTURE.md`, `docs/THREAT-MODELS.md`, `setup.py`,
  `requirements-lock.txt`~~ DONE — all filled in for real (not stubs).
  `requirements-lock.txt` carries an explicit provenance note that it's
  a best-effort placeholder (pinned lower bounds), not a real `pip
  freeze` output — regenerate it on a machine with network access.
  Docker assets are written but **not build-tested** (no Docker/network
  access in this sandbox) — someone with a provisioned machine should
  run `docker build` / `docker compose up` and fix forward.
- ~~3 of 4 demo pcaps (`ddos.pcap`, `dga.pcap`, `normal.pcap`) were 0
  bytes~~ DONE — generated via a new dependency-free (stdlib-only)
  generator, `scripts/generate_test_data_stdlib.py`, since `scapy`
  (required by the original `scripts/generate_test_data.py`) isn't
  installed in this sandbox. Structurally validated with an
  independent stdlib pcap parser. **Not yet validated end-to-end**
  against the real detection pipeline — run
  `python3 scripts/run_pipeline.py demo/ddos.pcap` (and `dga.pcap`,
  `normal.pcap`) on a machine with scapy/nfstream installed and confirm
  each trips (or, for `normal.pcap`, does NOT trip) the intended
  detector. If it doesn't, prefer adjusting the stdlib generator's
  parameters over hand-editing the pcap bytes.

### 8. Alert schema rebuild (Section 15) — do after 1-6 above
Once source-IP stats, SYN/UDP-specific detectors, and evidence fusion
exist, the `DDoSResult`/`Alert` schema should be extended properly:
`source_count`, `source_entropy`, `attack_subtype`, `supporting_evidence`
as a structured field (not just a loose `details` dict), `window_id`. Do
this after the upstream detectors exist so you're not guessing at the
shape — build the schema to fit real evidence, not a spec list.

### Do NOT do yet (explicitly out of scope until the above is solid)
- Full dashboard/UI redesign (Section 35-45 in the original brief) — the
  brief itself says correctness first, UI last (Section 57, Steps 12-13
  are near the end).
- ML model work beyond making sure it stays clearly separated from rule
  scores (Section 18) — don't force unfinished ML into DDoS.
- CTI enrichment wiring for DDoS specifically, unless it's already
  providing meaningful signal (Section 17 says don't force it).
- Full README/architecture-diagram rewrite (Section 46-47) — do this once
  the underlying system it's documenting has actually stabilized, or
  you'll just have to rewrite the docs again.

---

## How to verify your own work (do this for every change)

1. `python3 -m py_compile` the file(s) you touched, then the whole
   `src/`, `scripts/`, `dashboard/`, `models/` trees, to catch anything
   you broke elsewhere.
2. Import-check every module you touched AND everything that imports it
   (`grep -rln "from src.X import\|import src.X"` to find them).
3. Write a dependency-free test file (pure Python, no scapy/nfstream/
   pytest required to run it) that specifically targets the bug/feature,
   following the `tests/test_window_rates.py` pattern.
4. Re-run the existing `tests/test_detectors.py` and `tests/test_features.py`
   suites (or their non-scapy-dependent subsets) to confirm no
   regressions — see `docs/AUDIT_PROGRESS.md` for how to do this without
   pytest installed, if you're in the same network-restricted situation.
5. Update `docs/AUDIT_PROGRESS.md` with what you did, what you verified,
   and what's still unverified — keep it honest and current so the NEXT
   agent after you doesn't have to re-discover any of this either.
6. Be explicit in your final summary to the user about what was verified
   here vs. what still needs a real machine with scapy/nfstream/pytest
   installed. Never claim something passed a real pytest run if you only
   ran a hand-rolled stub collector.
