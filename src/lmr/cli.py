import argparse
import shutil
import sys
from pathlib import Path

from lmr import __version__
from lmr.input_check import inspect_capture_file, UnsupportedFileFormatError
from lmr.zeek_runner import run_zeek, ZeekExecutionError
from lmr.parsers.zeek_tsv import parse_zeek_tsv
from lmr.schema import normalize_zeek_logs
from lmr.detections.psexec import detect_psexec
from lmr.detections.winrm import detect_winrm
from lmr.graph import build_attack_graph, analyze_graph_metrics
from lmr.report import export_findings
from lmr.evidence import export_evidence_filters
from lmr.detections.rdp import detect_rdp
from lmr.detections.wmi import detect_wmi
from lmr.detections.smb import detect_smb
from lmr.detections.ssh import detect_ssh
from lmr.detections.linux_infra import detect_linux_infra
from lmr.detections.kerberos import detect_kerberos
from lmr.detections.ntlm import detect_ntlm
from lmr.report import export_findings, export_interactive_html


def run_doctor() -> None:
    """Inspects the host environment for required dependencies."""
    print(f"lmr v{__version__} System Check\n" + "-" * 40)
    print(f"Python Version: {sys.version.split()[0]}")

    zeek_path = shutil.which("zeek")
    if zeek_path:
        print(f"[OK] Local Zeek found: {zeek_path}")
    else:
        print("[INFO] Local Zeek not found (Normal for Windows users).")

    docker_path = shutil.which("docker")
    if docker_path:
        print(f"[OK] Docker found: {docker_path}")
    else:
        print("[!] Docker not found.")

    print("-" * 40)
    if docker_path or zeek_path:
        print("[READY] System meets the requirements to analyze packet captures.")
    else:
        print(
            "[ERROR] Neither Zeek nor Docker is installed.\n"
            "To analyze PCAPs, you must install Docker Desktop (Windows/macOS)\n"
            "or install Zeek locally (Linux).\n"
            "Download Docker: https://www.docker.com/products/docker-desktop/"
        )


def run_analyze(args: argparse.Namespace) -> None:
    """Main analysis pipeline: validates input, runs Zeek, runs detections, builds graph."""
    case_name = args.case
    out_dir = Path("out") / case_name
    out_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"[*] Starting analysis for case: {case_name}")
    
    if args.zeek_logs:
        log_dir = Path(args.zeek_logs)
        if not log_dir.is_dir():
            print(f"[!] Error: Zeek logs directory not found at {log_dir}")
            sys.exit(1)
        print(f"[*] Using existing Zeek logs from: {log_dir}")
        generated_logs = sorted([p.name for p in log_dir.glob("*.log")])
        
    elif args.capture:
        capture_path = Path(args.capture)
        try:
            capture_format = inspect_capture_file(capture_path)
            print(f"[*] Validated input capture: {capture_path.name} ({capture_format.value})")
        except (FileNotFoundError, UnsupportedFileFormatError) as e:
            print(f"[!] Input Error: {e}")
            sys.exit(1)
            
        log_dir = out_dir / "zeek_logs"
        print("[*] Executing Zeek (this may take a moment)...")
        try:
            result = run_zeek(capture_path, log_dir, force_docker=args.force_docker)
            generated_logs = result.generated_logs
        except ZeekExecutionError as e:
            print(f"[!] Zeek Error: {e}")
            sys.exit(1)
    else:
        print("[!] Error: You must provide either a capture file or --zeek-logs.")
        sys.exit(1)
        
    if not generated_logs:
        print("[!] No Zeek logs found or generated. Analysis cannot proceed.")
        sys.exit(1)

    print("[*] Running detection engine...")
    
    # Robust dynamic log ingestion mapping
    all_events = []
    log_file_mapping = {
        "smb_mapping.log": "smb_mapping",
        "smb_files.log": "smb_files",
        "dce_rpc.log": "dce_rpc",
        "http.log": "http",
        "rdp.log": "rdp",
        "ssh.log": "ssh",
        "conn.log": "conn",
        "kerberos.log": "kerberos",
        "ntlm.log": "ntlm",
    }

    loaded_logs_count = 0
    for log_filename, log_type in log_file_mapping.items():
        log_path = log_dir / log_filename
        if log_path.is_file():
            try:
                raw_data = list(parse_zeek_tsv(log_path)) # <--- Cast to list here
                if raw_data:
                    normalized = list(normalize_zeek_logs(log_type, raw_data)) # <--- Cast to list here
                    all_events.extend(normalized)
                    loaded_logs_count += 1
                    print(f"[*] Loaded {len(normalized)} events from {log_filename}")
            except Exception as e:
                print(f"[!] Warning: Failed to parse {log_filename}: {e}")

    if loaded_logs_count == 0:
        print("[!] Warning: No recognizable Zeek log files contained data records.")

    # Run all detection modules securely with error handling
    findings = []
    detectors = [
        ("PsExec", detect_psexec),
        ("WinRM", detect_winrm),
        ("RDP", detect_rdp),
        ("WMI/DCOM", detect_wmi),
        ("SMB Admin Share", detect_smb),
        ("SSH", detect_ssh),
        ("Linux Infrastructure", detect_linux_infra),
        ("Kerberos", detect_kerberos),
        ("NTLM", detect_ntlm)
    ]

    for name, detector_func in detectors:
        try:
            module_findings = list(detector_func(all_events))
            if module_findings:
                findings.extend(module_findings)
        except Exception as e:
            print(f"[!] Warning in {name} detector: {e}")
    
    print(f"[+] Detection complete. Found {len(findings)} lateral movement behaviors.")
    for f in findings:
        print(f"    -> [{f.confidence}] {f.title} ({f.src_ip} -> {f.dst_ip})")
        
    # Build the attack graph
    graph = build_attack_graph(findings)
    print(f"[+] Attack graph generated: {len(graph.nodes)} hosts, {len(graph.edges)} connections.")
    
    # Export results to disk
    print("[*] Generating reports (JSON, CSV)...")
    export_findings(findings, out_dir)

    print("[*] Generating evidence filters...")
    export_evidence_filters(findings, out_dir)

    metrics = analyze_graph_metrics(graph)
    html_path = out_dir / "report.html"
    print("[*] Generating interactive attack graph webpage...")
    export_interactive_html(findings, metrics, html_path)
    print(f"[+] Interactive visualizer saved to: {html_path.absolute()}")
    
    print(f"[+] Analysis complete. Results saved to: {out_dir.absolute()}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="lmr",
        description="Lateral Movement Reconstructor (lmr) - Automated DFIR network analysis.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    subparsers.add_parser(
        "doctor", help="Check system dependencies (Zeek, Docker) and provide guidance."
    )

    analyze_parser = subparsers.add_parser(
        "analyze", help="Analyze a packet capture or existing Zeek logs."
    )
    analyze_parser.add_argument(
        "capture", nargs="?", help="Path to the .pcap or .pcapng file"
    )
    analyze_parser.add_argument(
        "--zeek-logs", help="Path to a directory of existing Zeek logs (skips Zeek execution)"
    )
    analyze_parser.add_argument(
        "--case", required=True, help="Case name (e.g., IR-001)"
    )
    analyze_parser.add_argument(
        "--force-docker", action="store_true", help="Force Zeek to run via Docker"
    )

    args = parser.parse_args()

    if args.command == "doctor":
        run_doctor()
    elif args.command == "analyze":
        run_analyze(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()