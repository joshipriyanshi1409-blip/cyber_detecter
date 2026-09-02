# Threat Models

This document describes what `cyber_detecter` does and does not detect,
what evidence each detector actually relies on, and where the line
between "signal that supports a hypothesis" and "proof" sits. It is
written to match the code as it exists in `src/detectors/` and
`src/features/`, not an aspirational feature list -- if a section below
looks less impressive than a marketing page would, that's intentional
(see the "must never merely LOOK implemented" principle carried through
`docs/AUDIT_PROGRESS.md` and `docs/NEXT_AGENT_PROMPT.md`).

## System-wide constraints

- **Strictly passive / read-only.** The system reads packets (from a
  PCAP file or a live interface) and flows derived from them. It never
  sends packets, never completes handshakes it wasn't already a
  bystander to, never blocks or reshapes traffic, and never decrypts
  TLS/QUIC. `src/ingest/live_capture.py` is explicitly documented for
  controlled lab use with permission, not unattended production
  deployment against traffic you don't control.
- **Metadata-based, not content-based**, for anything beyond DNS. TLS-
  and QUIC-carried traffic is analyzed only via flow-level metadata
  (packet sizes, timing, byte/packet ratios) — never by inspecting or
  decrypting payload.
- **Evidence, not verdicts.** Every detector reports likelihood/
  evidence/confidence fields, never a bare "confirmed attack" claim.
  Rule-based (`rule_score`) and ML-based (`ml_probability`) scores are
  always kept separate; a score that wasn't computed is `None`, not a
  fabricated `0`.
- **False positives are expected and by design tolerated in favor of
  transparency.** Nearly every scenario below has a legitimate-traffic
  analog (a CDN, a NAT gateway, a backup job, a monitoring probe) that
  can partially resemble the attack pattern. The multi-factor gating
  described per-detector below exists specifically to reduce — not
  eliminate — those false positives, and every result carries the
  evidence that produced it so a human can make the final call.

## Detector-by-detector

### Port scanning (`src/detectors/scan.py`)

**What it looks for:** a single source contacting an unusually large
number of distinct ports and/or hosts in a window, with a high ratio of
connections that never complete (`syn_only_count`, distinguishing
"no response at all" from `failed_connections` gated on actually-seen
`rst_packets`, i.e. "actively refused").

**What it does NOT claim:** it cannot see the scanning tool, the
attacker's intent, or whether the target machine was actually
compromised — only that a connection pattern consistent with scanning
was observed. A misconfigured client retrying a dead service, or a
legitimate network-monitoring tool, can produce a similar shape.

### DDoS / volumetric flooding (`src/detectors/ddos.py`)

**What it looks for:** aggregate packet/byte rate against a
destination that exceeds a windowed threshold (via
`src/features/window_rates.py`, the corrected windowed-rate
implementation — not a naive `sum(duration)` aggregate, which was a
previously-fixed bug), corroborated by SYN ratio and source
concentration (via `src/features/source_stats.py`).

**What it does NOT claim:** it cannot distinguish a real DDoS from a
legitimate traffic spike (a viral link, a flash sale, a misconfigured
retry storm) from flow metadata alone — that's exactly why it requires
multiple corroborating factors rather than raw volume alone, and why
results carry `evidence` describing which factors fired.

### SYN flood (`src/detectors/syn_flood.py`)

**What it looks for:** a two-level analysis (aggregate across all
traffic, and per-destination) of SYN rate, handshake-completion ratio
(`syn_only_packets` vs `syn_ack_packets`), and destination
concentration, requiring **at least 2 of 3 factors** to cross
threshold — deliberately never deciding on a single ratio, because a
naturally SYN-heavy but legitimate workload (e.g. a load-testing tool,
a service with very short-lived connections) can push one ratio high
on its own without being an attack. Per-destination analysis also
folds in `one_packet_source_ratio` from `source_stats.py`.

**Spoofing evidence, and its limits:** `src/features/
spoofing_likelihood.py` produces a `spoofing_likelihood` score (never
below `MIN_SOURCES_FOR_SCORE = 5` distinct sources, otherwise reported
as `"insufficient_data"` rather than a misleadingly precise low score)
from source-entropy, one-packet-source ratio, and destination
concentration. This is **evidence of a pattern consistent with IP
spoofing**, not proof — the system has no mechanism (e.g. BGP path
validation, ingress filtering visibility) to actually confirm a source
address is forged. A fourth intended signal, `source_churn` (sources
appearing/disappearing across time windows), is always reported as
unavailable because the streaming/windowing mechanism it needs
(`docs/NEXT_AGENT_PROMPT.md` item 6) doesn't exist yet — it is never
silently approximated from a single window.

### UDP flood + reflection-like traffic (`src/detectors/udp_flood.py`)

**Two related but distinct threat types**, both produced by the same
detector:

- `UDP_FLOOD`: high-volume UDP traffic at one or few destinations,
  same two-level / >=2-factor structure as the SYN-flood detector.
- `UDP_REFLECTION_LIKE`: flows grouped by destination IP+port showing
  the byte/packet asymmetry characteristic of reflection/amplification
  abuse, corroborated by the destination port being a commonly-abused
  reflection service port and by source diversity — also gated on
  >=2 factors.

**Why reflection can only ever be "_LIKE":** a real
reflection/amplification attack has three logical parties (attacker,
reflector, victim), but this system only observes traffic from a
single vantage point after the fact. It can observe the asymmetric
shape a reflection attack produces at the victim's vantage point, but
it cannot see the spoofed request that supposedly triggered it or
independently confirm the third party's involvement. Every
`UDP_REFLECTION_LIKE` result carries an explicit interpretive caveat in
its `details` for exactly this reason — it is a name chosen
deliberately to avoid overclaiming, not a stylistic choice.

### DGA / suspicious domain names (`src/detectors/dga.py`)

**What it looks for:** domain names queried over DNS that score highly
on entropy and structural features (`src/features/entropy.py`:
Shannon entropy, n-gram scoring, digit/vowel/consonant ratios) that are
statistically associated with algorithmically-generated domains, minus
an explicit whitelist of common legitimate domains.

**What it does NOT claim:** high-entropy domain names are also
produced by legitimate CDN/cloud-provider naming schemes, URL
shorteners, and some ordinary product/brand names. This detector flags
a domain as *suspicious*, not as confirmed malware C2 — and has no
visibility into what the domain actually resolves to, hosts, or
whether it's on any live blocklist unless CTI enrichment
(`src/cti/`) separately corroborates it.

## Explicitly out of scope for detection today

These are named in `docs/NEXT_AGENT_PROMPT.md` as deliberately
deferred, not silently missing:

- **C2 beaconing** (periodic low-volume callback traffic) — no
  dedicated detector yet.
- **DNS tunnelling** beyond the DGA entropy angle above — no dedicated
  detector for high-frequency/high-volume DNS-as-a-channel patterns
  yet.
- **Data exfiltration** by volume/destination-reputation — no
  dedicated detector yet.
- **Encrypted-traffic metadata analysis** beyond what the flooding
  detectors already see incidentally (packet size/timing shape) — no
  dedicated TLS/QUIC fingerprinting detector yet.
- **ML-based anomaly/classification scoring in the decision path** —
  `src/models/` exists and is trainable, but is not wired into any
  detector's verdict. See `docs/ARCHITECTURE.md`, "ML status."

Extensibility for all of the above was an explicit design constraint
carried through the audit (don't build DDoS-specific plumbing that
makes these harder to add later) — see
`docs/NEXT_AGENT_PROMPT.md`.

## Alert integrity, not alert authority

`src/blockchain/hash_chain.py` provides a SHA-256 hash chain over
emitted alerts so that tampering with historical alert records after
the fact is detectable. This addresses *integrity of the record*, not
*correctness of the underlying detection* — a hash chain proves an
alert wasn't silently altered after being written, it says nothing
about whether the detector was right to raise it. The module's own
docstring is explicit that this is not a blockchain (no consensus, no
distributed ledger, no external validators) to avoid overclaiming what
a purely local, single-writer hash chain provides.
