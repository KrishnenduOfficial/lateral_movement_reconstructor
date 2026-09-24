# Lateral Movement Reconstructor (LMR)

<div align="center">

[![LMR CI Pipeline](https://github.com/your-username/lateral_movement_detector/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/lateral_movement_detector/actions/workflows/ci.yml)
![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

<p><strong>Automated DFIR Network Analysis & Threat Hunting Engine</strong></p>

</div>

---

## Overview

**Lateral Movement Reconstructor (LMR)** is an automated Incident Response pipeline designed to ingest network packet captures (`.pcap`/`.pcapng`) and Zeek logs, detect lateral movement behaviors without alert flooding, and generate interactive graph visualizations. 

Built specifically for SOC analysts and incident responders, LMR replaces noisy, per-packet security alerts with high-fidelity, host-to-host pivot chains mapped directly to the **MITRE ATT&CK®** framework.

---

## Key Features

* **Streaming Deduplication Engine:** Implements the `seen_states` deduplication pattern to compress tens of thousands of raw network frames into actionable, unique attack edges while preserving protocol-level details.
* **Multi-Protocol ATT&CK Detection:** Out-of-the-box analyzers covering primary enterprise pivot methods:
  * **PsExec / Service Execution:** Remote service creation over SMB/DCE-RPC.
  * **WinRM:** Remote PowerShell administration over HTTP/HTTPS.
  * **RDP:** Remote Desktop ingress, egress, and lateral sessions.
  * **SMB:** Administrative share access (`ADMIN$`, `C$`, `IPC$`).
  * **WMI / DCOM:** Remote process invocation.
  * **SSH & Linux Infrastructure:** Pivot paths targeting Linux servers.
  * **Kerberos & NTLM:** Authentication protocol inspection and credential relay detection.
* **Dual Ingestion Engine:** Automates Zeek parsing (locally on Linux or containerized via Docker on Windows/macOS) or ingests pre-existing Zeek TSV logs directly.
* **Interactive Attack Graphs:** Automatically compiles findings into standalone, interactive HTML reports featuring visual graph exploration, blast radius calculation, and triage metrics.
* **Forensic Evidence Filters:** Exports ready-to-use Wireshark display filters and Zeek query strings corresponding directly to detected incidents.

---

## Architecture Pipeline

```text
[ Raw PCAP / PCAPNG ] 
          │
          ▼
   Zeek Parser Layer (Native or Dockerized)
          │
          ▼
  Log Normalization (Schema mapping, null byte/empty set handling)
          │
          ▼
 Detection Engine (9 Independent ATT&CK modules with streaming dedup)
          │
          ▼
   NetworkX Graph Assembly & Metric Analysis
          │
          ▼
[ Evidence Artifacts: report.html | findings.json | evidence_filters.csv ]

```

---

## System Requirements

* **Python:** Version 3.11 or 3.12
* **Packet Dissection Engine:**
* **Linux:** Local `zeek` installation in `PATH`.
* **Windows / macOS:** [Docker Desktop](https://www.docker.com/products/docker-desktop/?utm_source=gemini) (used to run an isolated, containerized Zeek analyzer).



---

## Installation

LMR uses modern PEP 621 packaging (`pyproject.toml`).

```bash
# 1. Clone the repository
git clone [https://github.com/your-username/lateral_movement_detector.git](https://github.com/your-username/lateral_movement_detector.git)
cd lateral_movement_detector

# 2. Set up virtual environment
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate

# On Windows:
.\.venv\Scripts\Activate.ps1

# 3. Install the package
pip install .

# For development and testing extras:
pip install -e ".[dev]"

```

---

## Usage

LMR provides an enterprise CLI powered by `rich-argparse`. View the full options list anytime with `lmr --help`.

### 1. Environment Verification (`doctor`)

Check local system dependencies (Zeek, Docker) before analyzing captures:

```bash
lmr doctor

```

### 2. PCAP Analysis (`analyze`)

Analyze a raw network capture file. Results are written directly to `out/<case_name>/`:

```bash
lmr analyze evidence.pcap --case IR-001

```

*(Both `analyze` and `analyse` are accepted).*

### 3. Containerized Zeek Execution

Force Zeek execution inside Docker (recommended for Windows environments without WSL):

```bash
lmr analyze evidence.pcapng --case Case001 --force-docker

```

### 4. Direct Zeek Log Ingestion

Bypass packet processing when dealing with existing Zeek logs (ideal for air-gapped or pre-triaged captures):

```bash
lmr analyze --zeek-logs ./logs/ --case Case002

```

---

## Output Structure

Each analysis produces an isolated investigation bundle under `out/<case_name>/`:

```text
out/<case_name>/
├── report.html             # Standalone interactive D3/NetworkX attack graph
├── findings.json           # Machine-readable telemetry for SIEM/SOAR ingestion
├── findings.csv            # Structured tabular summary of all alerts
├── evidence_filters.csv    # Ready-to-paste Wireshark display filters per finding
└── zeek_logs/              # Raw generated TSV logs preserved for chain of custody

```

---

## Verification & CI/CD

LMR enforces strict type checking and automated regression testing across all modules.

```bash
# Run the complete test suite
pytest -v

# Run static type validation
mypy src/lmr

```

Continuous Integration is managed via GitHub Actions across both Python 3.11 and 3.12 environments.

---

## Author

**Krishnendu Bhattacherjee**
