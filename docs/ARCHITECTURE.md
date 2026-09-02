# Architecture

This document describes how `cyber_detecter` is put together as of this
pass. It reflects the code as it actually exists in `src/` — see
`docs/AUDIT_PROGRESS.md` for the history of what was found and fixed to
get it here, and `docs/NEXT_AGENT_PROMPT.md` for what's still open.
This is descriptive documentation of a stabilizing prototype, not a
promise of a finished product — several pieces below are explicitly
marked as partial or not-yet-wired.

## Design principles

- **Passive, read-only analysis.** No active probing, no packet
  injection, no blocking, no TLS/QUIC decryption. See
  `docs/THREAT-MODELS.md`.
- **Evidence over verdicts.** Detectors report `*_likely` scores,
  `evidence`, and `confidence` — never a bare "this IS an attack"
  claim. Rule-based scores (`rule_score`) and ML scores
  (`ml_probability`) are kept in separate fields and never merged; a
  field that hasn't been computed is `None`, never `0`.
- **Distinguish "missing" from "zero."** A detector that couldn't
  compute a signal (not enough data, a required upstream feature
  unavailable) says so explicitly rather than defaulting to a
  zero-value that looks like a real "no signal detected" result. See
  `src/features/window_rates.py` for the reference pattern.
- **Two-or-more-factor gating.** The flooding detectors
  (`syn_flood.py`, `udp_flood.py`, `ddos.py`) never fire on a single
  ratio crossing a threshold in isolation; they require at least two
  independent signals to agree. A single noisy metric is not enough
  evidence on its own.

## Data flow (batch / offline path)

```
PCAP file
   |
   v
src/ingest/pcap_reader.py          (Scapy: rdpcap / PcapReader)
   |  raw packets
   v
src/flow/flow_analyzer.py           --------------+
src/flow/nfstream_wrapper.py        (nfstream if   |  bidirectional
                                      installed,    |  FlowRecord objects
                                      else a Scapy   |
                                      fallback)      |
   |                                                 |
   v                                                 |
src/features/                        <---------------+
  window_rates.py    -- correct windowed rate calculation (the
                         reference pattern for windowed math)
  source_stats.py    -- per-window source/destination distribution,
                         concentration (HHI), entropy
  spoofing_likelihood.py -- weighted composite score built from
                         source_stats output (never raw flows)
  rate.py / entropy.py / network_features.py -- legacy feature
                         extraction feeding the ML models
   |
   v
src/detectors/
  scan.py        -- PortScanDetector
  ddos.py        -- DDoSDetector (aggregate volumetric)
  syn_flood.py   -- SynFloodDetector (SYN-specific, two-level:
                     aggregate + per-destination)
  udp_flood.py   -- UDPFloodDetector (UDP_FLOOD +
                     UDP_REFLECTION_LIKE, two-level)
  dga.py         -- DGADetector (domain entropy/structure)
   |  each produces its own *Result dataclass
   v
src/detectors/detector_factory.py   -- DetectorFactory / DetectorType,
                                        runs all registered detectors
                                        via run_all_detectors
   |
   v
src/alerts/alert_engine.py          -- AlertEngine/AlertProcessor:
                                        detection-result -> standardized
                                        Alert (alert_models.py), with
                                        time-window deduplication
   |
   +--> src/scoring/risk_score.py    -- RiskScoreCalculator: combines
   |                                    evidence sources into a unified
   |                                    risk_score + severity
   |
   +--> src/cti/enrichment.py        -- ThreatIntelligenceEnricher
   |      src/cti/providers.py         (local list + optional ThreatFox)
   |
   +--> src/blockchain/hash_chain.py -- SHA-256 hash chain over alerts
   |                                    for tamper-evident audit log
   |                                    (NOT a blockchain -- no
   |                                    consensus, no distribution;
   |                                    the module docstring says so
   |                                    explicitly)
   |
   v
src/storage/database.py             -- SQLAlchemy ORM, SQLite by
                                        default (config/config.yaml:
                                        database.path)
   |
   v
dashboard/app.py                    -- Streamlit UI reading from the
                                        database (DatabaseManager,
                                        Alert / AlertSeverity)
```

`src/streaming/pipeline.py` (`ThreatDetectionPipeline`) wires the
ingestion -> flow -> detection -> alerting -> storage steps together
for both the batch CLI (`scripts/run_pipeline.py`) and live-capture
entrypoints. It also holds `src/models/isolation_forest.py` and
`src/models/random_forest.py`, the ML side -- currently kept
deliberately decoupled from the rule-based DDoS decision path (see
"ML status" below).

## Live capture path

`src/ingest/live_capture.py` (`LivePacketCapture`, built on
`scapy.all.sniff`) is the live-interface equivalent of
`pcap_reader.py`. It is explicitly documented in its own module
docstring as **for controlled lab environments with permission only**.
The Docker/compose setup (`docker/docker-compose.yml`) does not enable
it by default -- it needs host networking and `CAP_NET_RAW`, which are
opt-in, commented-out configuration, not a default.

## Configuration

- `config/config.yaml` -- app-level settings: logging, database path,
  data directories, which detectors are enabled by default, ML
  hyperparameters, streaming batch size / window.
- `config/thresholds.yaml` -- per-detector numeric thresholds (packet
  rates, ratios, window sizes). Each detector module has a matching
  fallback default set in `src/utils/config_simple.py`
  (`DEFAULT_THRESHOLDS`) used when the full YAML-based
  `src/utils/config.py` loader can't be used (e.g. PyYAML missing).
- `env.example` -- CTI provider API keys (`THREATFOX_API_KEY`,
  `URLHAUS_API_KEY`, `MALWAREBAZAAR_API_KEY`), all optional; the CTI
  enricher defaults to `LocalThreatIntelligenceProvider` (no network
  calls) when none are set.

## Streaming/windowing status (important known gap)

There is currently **no real sliding-window mechanism**.
`src/streaming/pipeline.py` is batch-only: either a whole PCAP loaded
into memory, or a live-capture loop with no bounded-memory windowing.
Several features are explicitly reported as unavailable because of
this rather than being faked:

- `source_stats.calculate_source_stats(...)`'s `source_churn` is
  always `None` with `source_churn_reason: "requires_streaming_window"`.
- `spoofing_likelihood.calculate_spoofing_likelihood(...)` always
  reports the churn signal as unavailable for the same reason.
- `FlowRateCalculator.get_aggregate_rates()` (`src/features/rate.py`)
  has a documented anchoring issue: because the underlying flow list
  is never trimmed, its `start_time` stays pinned to the first flow
  the process ever saw, so long-running processes increasingly report
  "rate since startup" rather than a true rolling rate.

This is tracked as `docs/NEXT_AGENT_PROMPT.md` item 6
(`src/streaming/windowing.py`, not yet started) and is called out as
architecturally important precisely because several other modules are
already built to slot into it once it exists, rather than needing to
be redesigned.

## ML status

`src/models/isolation_forest.py` (unsupervised anomaly scoring) and
`src/models/random_forest.py` (supervised classification) exist and
are trainable via `scripts/train_model.py`, but are **not currently
wired into any detector's decision path**. `ml_probability` fields on
detection results are `None` throughout the rule-based detectors on
purpose -- per the project's non-negotiable rule, a rule-based decision
must never borrow or backfill an ML-shaped field it didn't actually
compute. Forcing ML into the DDoS path before it's properly validated
is explicitly out of scope for now (see
`docs/NEXT_AGENT_PROMPT.md`, "Do NOT do yet").

## Testing architecture

Two parallel sets of tests exist:

- `tests/test_*.py` files that import `pytest` and, in several cases,
  `scapy` at module level. These require a fully provisioned
  environment (see `requirements.txt`) and could not be run or even
  imported in the sandbox used for the audit passes recorded in
  `docs/AUDIT_PROGRESS.md`.
- A growing set of **dependency-free** test files
  (`tests/test_window_rates.py`, `test_source_stats.py`,
  `test_spoofing_likelihood.py`, `test_syn_flood.py`,
  `test_udp_flood.py`, `test_scan_failure_signatures.py`,
  `test_rate_calculator.py`, `test_entropy.py`, ...) written in pure
  Python with hand-built `FakeFlow`-style dataclasses instead of real
  `scapy`/`nfstream` objects, each runnable standalone with
  `python3 tests/test_X.py`. These are what verified every fix
  recorded in `docs/AUDIT_PROGRESS.md` in environments without network
  access. They are a genuine safety net, but they are **not a
  substitute** for a real `pytest` run against the full dependency set
  -- see that document for the exact scope of what has and hasn't been
  verified for real.

## Directory map

```
src/
  ingest/      -- PCAP + live capture readers
  flow/        -- flow extraction (nfstream + Scapy fallback)
  features/    -- windowed rates, source stats, spoofing likelihood,
                  entropy, legacy rate/network feature extraction
  detectors/   -- scan, ddos, syn_flood, udp_flood, dga, factory
  scoring/     -- unified risk scoring
  alerts/      -- alert models, engine, validation
  cti/         -- threat-intel providers + enrichment
  blockchain/  -- SHA-256 hash-chain audit log (not a blockchain)
  storage/     -- SQLAlchemy/SQLite persistence
  streaming/   -- pipeline orchestration (windowing not yet built)
  models/      -- ML models (isolation forest, random forest)
  utils/       -- config loading, logging
scripts/       -- CLI entry points (run_pipeline, run_dashboard,
                  train_model, generate_test_data, ...)
dashboard/     -- Streamlit UI
tests/         -- pytest-based tests + dependency-free equivalents
demo/          -- sample PCAPs for each detector scenario
docker/        -- Dockerfile + docker-compose.yml
docs/          -- this file, THREAT-MODELS.md, and the audit trail
```
