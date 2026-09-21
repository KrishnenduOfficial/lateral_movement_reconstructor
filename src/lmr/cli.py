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
from lmr.graph.builder import build_attack_graph
from lmr.report import export_findings


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
    
    # Check for required logs before running specific detections
    all_events = []
    
    if "smb_mapping.log" in generated_logs:
        raw_smb = parse_zeek_tsv(log_dir / "smb_mapping.log")
        all_events.extend(normalize_zeek_logs("smb_mapping", raw_smb))
        
    if "dce_rpc.log" in generated_logs:
        raw_rpc = parse_zeek_tsv(log_dir / "dce_rpc.log")
        all_events.extend(normalize_zeek_logs("dce_rpc", raw_rpc))
        
    # Run the PsExec detection over the combined events
    findings = list(detect_psexec(all_events))
    
    print(f"[+] Detection complete. Found {len(findings)} lateral movement behaviors.")
    for f in findings:
        print(f"    -> [High] {f.title} ({f.src_ip} -> {f.dst_ip})")
        
    # Build the attack graph
    graph = build_attack_graph(findings)
    print(f"[+] Attack graph generated: {len(graph.nodes)} hosts, {len(graph.edges)} connections.")
    
    # Export results to disk
    print("[*] Generating reports (JSON, CSV)...")
    export_findings(findings, out_dir)
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