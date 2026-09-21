# Lateral Movement Reconstructor (lmr)

Reconstruct attacker lateral movement from a network capture, and see the proof behind every finding.

> **Status: Milestone 1 Complete (Active Development).** The core analysis pipeline (Zeek execution, log parsing, unified schema, detection engine, and attack graph builder) is functional. The CLI successfully detects PsExec lateral movement. Final report generation (HTML/JSON) and remaining detections are currently in development.

## What it does

Give it a PCAP (or existing Zeek logs). It will:

1. Discover protocols, hosts, ports, domains, and accounts on its own, with no port or protocol input from you.
2. Detect lateral movement techniques.
3. Rebuild the attacker's path across hosts as a graph and timeline.
4. Produce a report where every finding shows exactly why it fired, with evidence you can verify independently.

## Design principles

- **One command.** You provide the capture path and a case name. Nothing else is required.
- **No port assumptions.** Detections rely on the protocol Zeek identifies plus behavior, not on a fixed port number alone.
- **Proof for every finding.** Each finding lists the matched conditions, the Zeek connection UIDs, timestamps, a Wireshark filter, and a PCAP slice of just that traffic.
- **Explainable confidence.** Scores show what raised and lowered them. No black box.
- **Honest limits.** The tool reports what it could not analyze, such as missing logs or encrypted traffic. It does not claim to detect everything.

## Supported detections (v0.1 Target)

| Technique | ATT&CK | Zeek evidence | Status |
|---|---|---|---|
| SMB / PsExec-style remote execution | T1021.002, T1569.002 | smb_mapping, smb_files, dce_rpc | Active |
| WinRM | T1021.006 | http, conn | Planned |
| RDP | T1021.001 | rdp | Planned |
| Kerberoasting | T1558.003 | kerberos | Planned |
| DCSync | T1003.006 | dce_rpc | Planned |
| NTLM / pass-the-hash (heuristic) | T1550.002 | ntlm | Planned |

*Out of scope for v0.1: C2 detection, malware analysis, machine learning, and WMI/DCOM/SSH lateral movement.*

## How it works
PCAP -> Zeek -> structured logs -> lmr -> report + evidence
(parse)                    (detect, correlate, graph, score)
Zeek does the protocol decoding. `lmr` does the detection, correlation, scoring, and reporting on top of it.

## Usage

```bash
lmr analyze capture.pcapng --case IR-001
lmr analyze --zeek-logs ./zeek-logs --case IR-002
lmr doctor
lmr doctor will check your machine and print setup instructions for Docker or Zeek.

Output (in development)
out/IR-001/
  report.html        interactive graph, timeline, finding cards
  findings.json      machine-readable findings
  findings.csv       for Excel or Timeline Explorer
  coverage.txt       what was analyzed and what was skipped
  manifest.json      input SHA-256, tool, rule, and Zeek versions
  evidence/          per-finding PCAP slices and Wireshark filters
Requirements
Python 3.11 or newer

One of: Docker (Zeek bundled in the image), a local Zeek install, or existing Zeek logs

Repository layout
src/lmr/          tool source code (CLI, runner, parsers, detections, graph)
tests/            unit tests and fixtures
docs/             notes, triage guides, dataset index
samples/          tiny sample logs
scripts/          helper scripts
Test data
Capture files are not stored in this repository. docs/dataset_index.csv lists the captures used for development, with sizes and SHA-256 hashes so results can be reproduced. Sources are public: CyberDefenders labs, the Zeek project's test traces, and WRCCDC competition captures. Credit belongs to their authors.

Roadmap
[x] Phase A: environment, Zeek verified, data organized, repository created

[x] Phase B: Zeek runner, memory-efficient TSV parser, unified event schema, first detection (SMB/PsExec), attack graph builder

[ ] Phase C: remaining detections, HTML/JSON/CSV reports, evidence PCAP slicing

[ ] Phase D: validation on labeled captures, Docker image, CI, v0.1.0 release

Known limitations
Encrypted SMB3 and WinRM payloads hide content. Detection there relies on metadata.

Requires Zeek, directly or through Docker, unless you supply Zeek logs.

NTLM / pass-the-hash detection is heuristic and will carry lower confidence.

Validation results have not been published yet.

AI Assistance Note
This project was developed via pair-programming with an AI assistant to accelerate implementation while maintaining strict architectural control.

Human (Author): Defined the project architecture, set zero-config tool constraints, designed the DFIR heuristics (SMB/PsExec correlation logic), curated the test datasets, performed local validation, and managed version control.

AI: Drafted the Python implementation (argparse CLI, subprocess Docker wrapping, generator-based TSV parsing, NetworkX graph logic) and wrote unit tests based on provided constraints.

License
MIT (license file to be added).

Author
Krishnendu Bhattacherjee