<div align="center">

# Lateral Movement Reconstructor (LMR)

**Automated DFIR network analysis: turn raw packet captures into evidence-backed lateral movement findings.**

[![CI](https://github.com/KrishnenduOfficial/lateral_movement_reconstructor/actions/workflows/ci.yml/badge.svg)](https://github.com/KrishnenduOfficial/lateral_movement_reconstructor/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

</div>

---

## Overview

LMR ingests a network capture (`.pcap` / `.pcapng`) or existing Zeek logs and reconstructs attacker lateral movement across a network — automatically, with no port or protocol input from the user. It compresses raw connection telemetry into deduplicated, host-to-host pivot chains mapped to MITRE ATT&CK®, and produces a self-contained interactive report where every finding shows the exact evidence behind it.

It is built for SOC analysts and incident responders who need to answer "how did the attacker move, and can I prove it?" — not just "was there suspicious traffic?"

## Design principles

- **Zero-config input.** Provide a capture path and a case name. Protocols, ports, hosts, and accounts are discovered automatically.
- **No port assumptions.** Detections rely on the protocol Zeek identifies plus behavior, not a hardcoded port.
- **Proof for every finding.** Each finding carries its matched conditions, Zeek connection UIDs, a ready-to-use Wireshark filter, and an ATT&CK mapping.
- **Honest about limits.** Encrypted payloads (SMB3, WinRM over HTTPS) hide content. LMR reports what it could and could not analyze rather than claiming full coverage.

## Detection coverage

| # | Module | ATT&CK Technique(s) | Primary evidence |
|---|---|---|---|
| 1 | SSH brute force / initial access | T1021.004, T1110 | conn, ssh |
| 2 | Linux persistence & privilege escalation | T1053.003, T1548.003 | conn, syslog-derived indicators |
| 3 | PsExec / remote service execution | T1021.002, T1569.002 | smb_mapping, smb_files, dce_rpc |
| 4 | SMB administrative share access | T1021.002 | smb_mapping, smb_files |
| 5 | WMI / DCOM remote execution | T1047 | dce_rpc |
| 6 | WinRM / PowerShell remoting | T1021.006 | http, conn |
| 7 | RDP lateral movement | T1021.001 | rdp |
| 8 | Kerberoasting | T1558.003 | kerberos |
| 9 | NTLM credential spraying & pass-the-hash | T1110.003, T1550.002 | ntlm |

Out of scope for this release: DNS tunneling / C2 beaconing, malware behavior analysis, and machine-learning-based anomaly detection.

## Architecture

```
capture (.pcap / .pcapng)
        │
        ▼
Zeek parser layer (native on Linux, or containerized via Docker on Windows/macOS)
        │
        ▼
Log normalization (schema mapping, empty/unset field handling)
        │
        ▼
Detection engine — 9 independent ATT&CK modules, streaming deduplication
        │
        ▼
Graph assembly & path analysis (NetworkX)
        │
        ▼
report.html · findings.json · findings.csv · evidence_filters.csv
```

Zeek decodes the protocols; LMR does the detection, correlation, deduplication, and graph analysis on top of it. The graph itself renders in the browser as a dependency-free, hand-built canvas visualization (force-directed layout, pan/zoom, click-to-inspect) — no D3 or external charting runtime required for the graph view.

## Requirements

- Python 3.11 or 3.12
- One of:
  - **Linux:** a local `zeek` install on `PATH`
  - **Windows / macOS:** [Docker Desktop](https://www.docker.com/products/docker-desktop/) (LMR runs Zeek in a container automatically)
  - Neither: supply pre-generated Zeek logs directly via `--zeek-logs`

## Installation

```bash
git clone https://github.com/KrishnenduOfficial/lateral_movement_reconstructor.git
cd lateral_movement_reconstructor

python -m venv .venv

# Linux/macOS
source .venv/bin/activate
# Windows
.venv\Scripts\Activate.ps1

pip install -e ".[dev]"
```

## Usage

```bash
# Check that Zeek/Docker are available and correctly configured
lmr doctor

# Analyze a capture (accepts .pcap or .pcapng)
lmr analyze evidence.pcap --case IR-001

# Force Zeek to run inside Docker (recommended on Windows without WSL)
lmr analyze evidence.pcapng --case IR-002 --force-docker

# Skip packet processing entirely and use existing Zeek logs
lmr analyze --zeek-logs ./logs/ --case IR-003
```

`analyze` and `analyse` are both accepted.

## Output

Each run writes an isolated investigation bundle:

```
out/<case_name>/
├── report.html             self-contained interactive attack graph and finding cards
├── findings.json           machine-readable findings, for SIEM/SOAR ingestion
├── findings.csv            tabular summary of all findings
├── evidence_filters.csv    ready-to-paste Wireshark filters, one per finding
└── zeek_logs/              the raw Zeek TSV logs generated for this case
```

`out/` is not committed to this repository (each run produces case-specific evidence); only a `.gitkeep` placeholder is tracked so the folder exists after cloning.

## Testing and CI

```bash
pytest -v
mypy src/lmr
```

GitHub Actions runs the test suite and type checks on every push, across Python 3.11 and 3.12.

## Project status

Core detection pipeline, Zeek integration, and the interactive report are implemented and passing CI. Known gaps and planned work:
- Validation results (precision/recall against labeled test captures) are being finalized and will be published here.
- A packaged Docker image (Zeek + LMR bundled) is planned for one-command analysis with no local install.
- Case write-ups demonstrating the tool against public captures are in progress.

## Test data

This repository does not include capture files. Development and testing used public sources (CyberDefenders labs, the Zeek project's test traces); see `docs/dataset_index.csv` for the exact files and hashes used.

## License

MIT — see [LICENSE](LICENSE).

## Author

**Krishnendu Bhattacherjee**