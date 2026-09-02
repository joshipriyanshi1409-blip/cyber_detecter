# syntax=docker/dockerfile:1
#
# cyber_detecter -- passive network threat detection prototype.
#
# NOTE on scope: this image installs the app and its declared
# dependencies (requirements.txt) and runs the batch pipeline / dashboard
# entry points. It intentionally does NOT set NET_ADMIN/NET_RAW
# capabilities or host networking by default (see the "live capture"
# service commented out in docker-compose.yml) -- the project is a
# passive analysis tool and live packet capture should be an explicit,
# reviewed opt-in, not a container default. See docs/THREAT-MODELS.md.
#
# This Dockerfile has NOT been build-tested in this sandbox: there is no
# network access here (see docs/AUDIT_PROGRESS.md /
# docs/NEXT_AGENT_PROMPT.md), so `docker build` -- which needs to reach
# PyPI and the Debian package mirrors -- cannot be exercised. Someone
# with a provisioned machine should run `docker build -f docker/Dockerfile .`
# and fix forward if anything here doesn't match reality.

FROM python:3.11-slim AS base

# Build/runtime system packages:
#  - libpcap-dev: required to build/run scapy's packet-capture bindings
#  - tcpdump: convenient for interactive debugging of pcap files in-container
#  - build-essential: some of numpy/scikit-learn's transitive deps still
#    need a compiler on slim images without prebuilt wheels for the pinned
#    versions
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev \
        tcpdump \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first so this layer is cached across code
# changes that don't touch requirements.txt.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY . .
RUN pip install --no-cache-dir -e .

# Non-root user. Live packet capture (raw sockets) needs CAP_NET_RAW,
# which is granted explicitly per-container in docker-compose.yml for
# the opt-in capture service only -- NOT for this default image.
RUN useradd --create-home --shell /bin/bash detecter \
    && mkdir -p /app/data /app/logs \
    && chown -R detecter:detecter /app
USER detecter

EXPOSE 8501

# Default: run the batch pipeline against the bundled port-scan demo
# pcap. Override the command to run the dashboard (see
# docker-compose.yml) or to point at a different pcap:
#   docker run cyber_detecter python scripts/run_pipeline.py demo/ddos.pcap
CMD ["python3", "scripts/run_pipeline.py", "demo/port_scan.pcap"]
