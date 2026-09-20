# Lateral Movement Reconstructor (lmr)

Reconstruct attacker lateral movement from a network capture, and see the proof behind every finding.

> **Status: early development.** The project skeleton, test dataset, and design are done. The CLI and detections are being built and are not usable yet. Everything under "Planned" describes the intended behavior, not what works today.

## What it will do

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

## Planned detections (v0.1)

| Technique | ATT&CK | Zeek evidence |
|---|---|---|
| SMB / PsExec-style remote execution | T1021.002, T1569.002 | smb_mapping, smb_files, dce_rpc |
| WinRM | T1021.006 | http, conn |
| RDP | T1021.001 | rdp |
| Kerberoasting | T1558.003 | kerberos |
| DCSync | T1003.006 | dce_rpc |
| NTLM / pass-the-hash (heuristic) | T1550.002 | ntlm |

Out of scope for v0.1: C2 detection, malware analysis, machine learning, and WMI/DCOM/SSH lateral movement.

## How it works

```
PCAP -> Zeek -> structured logs -> lmr -> report + evidence
       (parse)                    (detect, correlate, graph, score)
```

Zeek does the protocol decoding. lmr does the detection, correlation, scoring, and reporting on top of it.

## Planned usage

```
lmr analyze capture.pcap --case IR-001
lmr analyze --zeek-logs ./zeek-logs --case IR-002
lmr doctor
```

`lmr doctor` will check your machine and print setup instructions.

## Planned output

```
out/IR-001/
  report.html        interactive graph, timeline, finding cards
  findings.json      machine-readable findings
  findings.csv       for Excel or Timeline Explorer
  coverage.txt       what was analyzed and what was skipped
  manifest.json      input SHA-256, tool, rule, and Zeek versions
  evidence/          per-finding PCAP slices and Wireshark filters
```

## Requirements (planned)

- Python 3.11 or newer
- One of: Docker (Zeek bundled in the image), a local Zeek install, or existing Zeek logs

## Repository layout

```
src/lmr/          tool source code
tests/            unit tests and fixtures
docs/             notes, triage guides, dataset index
samples/          tiny sample logs
scripts/          helper scripts
```

## Test data

Capture files are not stored in this repository. `docs/dataset_index.csv` lists the captures used for development, with sizes and SHA-256 hashes so results can be reproduced. Sources are public: CyberDefenders labs, the Zeek project's test traces, and (planned) WRCCDC competition captures. Credit belongs to their authors.

## Roadmap

- [x] Phase A: environment, Zeek verified, data organized, repository created
- [ ] Phase B: Zeek runner, log parser, first detection (SMB/PsExec)
- [ ] Phase C: remaining detections, attack-path graph, HTML/JSON/CSV reports
- [ ] Phase D: validation on labeled captures, Docker image, CI, v0.1.0 release

## Known limitations

- Encrypted SMB3 and WinRM payloads hide content. Detection there relies on metadata.
- Requires Zeek, directly or through Docker, unless you supply Zeek logs.
- NTLM / pass-the-hash detection is heuristic and will carry lower confidence.
- Validation results have not been published yet.

## License

MIT (license file to be added).

## Author

Krishnendu Bhattacherjee