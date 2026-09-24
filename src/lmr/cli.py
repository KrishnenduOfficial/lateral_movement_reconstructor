import argparse
import shutil
import sys
from pathlib import Path

from rich.console import Console
from rich_argparse import RichHelpFormatter

from lmr import __version__
from lmr.input_check import inspect_capture_file, UnsupportedFileFormatError
from lmr.zeek_runner import run_zeek, ZeekExecutionError
from lmr.parsers.zeek_tsv import parse_zeek_tsv
from lmr.schema import normalize_zeek_logs
from lmr.detections.psexec import detect_psexec
from lmr.detections.winrm import detect_winrm
from lmr.graph import build_attack_graph, analyze_graph_metrics
from lmr.report import export_findings, export_interactive_html
from lmr.evidence import export_evidence_filters
from lmr.detections.rdp import detect_rdp
from lmr.detections.wmi import detect_wmi
from lmr.detections.smb import detect_smb
from lmr.detections.ssh import detect_ssh
from lmr.detections.linux_infra import detect_linux_infra
from lmr.detections.kerberos import detect_kerberos
from lmr.detections.ntlm import detect_ntlm

# Initialize Rich Console
console = Console()

# --- ENTERPRISE CLI STYLING ---
RichHelpFormatter.styles["argparse.args"] = "bold cyan"
RichHelpFormatter.styles["argparse.groups"] = "bold bright_blue"
RichHelpFormatter.styles["argparse.help"] = "white"
RichHelpFormatter.styles["argparse.metavar"] = "bold yellow"
RichHelpFormatter.styles["argparse.prog"] = "bold bright_magenta"

class LMRFormatter(RichHelpFormatter):
    """Custom formatter for a polished, industry-grade CLI menu."""
    usage_markup = True
    group_name_formatter = str.upper

def print_banner():
    banner = f"""[bold bright_cyan]
██╗     ███╗   ███╗██████╗ 
██║     ████╗ ████║██╔══██╗
██║     ██╔████╔██║██████╔╝
██║     ██║╚██╔╝██║██╔══██╗
███████╗██║ ╚═╝ ██║██║  ██║
╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝ [white]v{__version__}[/white]
[/bold bright_cyan][bold white]Lateral Movement Reconstructor[/bold white]
[dim]Advanced DFIR Network Analysis & Threat Hunting Engine[/dim]
"""
    console.print(banner)

def run_doctor() -> None:
    """Inspects the host environment for required dependencies."""
    console.print(f"\n[bold white]LMR v{__version__} System Check[/bold white]")
    console.print("[dim]" + "━" * 50 + "[/dim]")
    console.print(f"[bold]Python Version:[/bold] {sys.version.split()[0]}")

    zeek_path = shutil.which("zeek")
    if zeek_path:
        console.print(f"[bold green][✓][/bold green] Local Zeek found: [cyan]{zeek_path}[/cyan]")
    else:
        console.print("[bold yellow][*][/bold yellow] Local Zeek not found [dim](Normal for Windows users).[/dim]")

    docker_path = shutil.which("docker")
    if docker_path:
        console.print(f"[bold green][✓][/bold green] Docker found: [cyan]{docker_path}[/cyan]")
    else:
        console.print("[bold red][!][/bold red] Docker not found.")

    console.print("[dim]" + "━" * 50 + "[/dim]")
    if docker_path or zeek_path:
        console.print("[bold green][READY][/bold green] System meets the requirements to analyze packet captures.\n")
    else:
        console.print(
            "[bold red][ERROR] Neither Zeek nor Docker is installed.[/bold red]\n"
            "To analyze PCAPs, you must install Docker Desktop (Windows/macOS)\n"
            "or install Zeek locally (Linux).\n"
            "[u bright_blue]Download Docker: https://www.docker.com/products/docker-desktop/[/u bright_blue]\n"
        )

def run_analyze(args: argparse.Namespace) -> None:
    """Main analysis pipeline: validates input, runs Zeek, runs detections, builds graph."""
    case_name = args.case
    out_dir = Path("out") / case_name
    out_dir.mkdir(parents=True, exist_ok=True)
    
    console.print(f"\n[bold bright_blue][*][/bold bright_blue] Starting analysis for case: [bold white]{case_name}[/bold white]")
    
    if args.zeek_logs:
        log_dir = Path(args.zeek_logs)
        if not log_dir.is_dir():
            console.print(f"[bold red][!][/bold red] Error: Zeek logs directory not found at [yellow]{log_dir}[/yellow]")
            sys.exit(1)
        console.print(f"[bold bright_blue][*][/bold bright_blue] Using existing Zeek logs from: [cyan]{log_dir}[/cyan]")
        generated_logs = sorted([p.name for p in log_dir.glob("*.log")])
        
    elif args.capture:
        capture_path = Path(args.capture)
        try:
            capture_format = inspect_capture_file(capture_path)
            console.print(f"[bold green][✓][/bold green] Validated input capture: [white]{capture_path.name}[/white] [dim]({capture_format.value})[/dim]")
        except (FileNotFoundError, UnsupportedFileFormatError) as e:
            console.print(f"[bold red][!][/bold red] Input Error: {e}")
            sys.exit(1)
            
        log_dir = out_dir / "zeek_logs"
        console.print("[bold bright_blue][*][/bold bright_blue] Executing Zeek [dim](this may take a moment)...[/dim]")
        try:
            result = run_zeek(capture_path, log_dir, force_docker=args.force_docker)
            generated_logs = result.generated_logs
        except ZeekExecutionError as e:
            console.print(f"[bold red][!][/bold red] Zeek Error: {e}")
            sys.exit(1)
    else:
        console.print("[bold red][!][/bold red] Error: You must provide either a capture file or --zeek-logs.")
        sys.exit(1)
        
    if not generated_logs:
        console.print("[bold red][!][/bold red] No Zeek logs found or generated. Analysis cannot proceed.")
        sys.exit(1)

    console.print("\n[bold bright_blue][*][/bold bright_blue] Running detection engine...")
    
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
                raw_data = list(parse_zeek_tsv(log_path)) 
                if raw_data:
                    normalized = list(normalize_zeek_logs(log_type, raw_data))
                    all_events.extend(normalized)
                    loaded_logs_count += 1
                    console.print(f"  [green]↳[/green] Loaded [bold]{len(normalized):,}[/bold] events from [cyan]{log_filename}[/cyan]")
            except Exception as e:
                console.print(f"  [bold yellow][!][/bold yellow] Warning: Failed to parse {log_filename}: {e}")

    if loaded_logs_count == 0:
        console.print("[bold yellow][!][/bold yellow] Warning: No recognizable Zeek log files contained data records.")

    findings = []
    detectors = [
        ("PsExec", detect_psexec),
        ("WinRM", detect_winrm),
        ("RDP", detect_rdp),
        ("WMI/DCOM", detect_wmi),
        ("SMB Admin Share", detect_smb),
        ("SSH", detect_ssh),
        ("Linux Infra", detect_linux_infra),
        ("Kerberos", detect_kerberos),
        ("NTLM", detect_ntlm)
    ]

    console.print("\n[bold bright_blue][*][/bold bright_blue] Executing ATT&CK analyzers...")
    for name, detector_func in detectors:
        try:
            module_findings = list(detector_func(all_events))
            if module_findings:
                findings.extend(module_findings)
        except Exception as e:
            console.print(f"  [bold yellow][!][/bold yellow] Warning in {name} detector: {e}")
    
    console.print(f"\n[bold green][+][/bold green] Detection complete. Found [bold red]{len(findings)}[/bold red] lateral movement behaviors.")
    for f in findings:
        console.print(f"    [dim]->[/dim] [[bold yellow]{f.confidence}[/bold yellow]] {f.title} ([cyan]{f.src_ip}[/cyan] -> [cyan]{f.dst_ip}[/cyan])")
        
    graph = build_attack_graph(findings)
    console.print(f"\n[bold green][+][/bold green] Attack graph generated: [bold]{len(graph.nodes)}[/bold] hosts, [bold]{len(graph.edges)}[/bold] connections.")
    
    console.print("[bold bright_blue][*][/bold bright_blue] Generating reports (JSON, CSV)...")
    export_findings(findings, out_dir)

    console.print("[bold bright_blue][*][/bold bright_blue] Generating evidence filters...")
    export_evidence_filters(findings, out_dir)

    metrics = analyze_graph_metrics(graph)
    html_path = out_dir / "report.html"
    console.print("[bold bright_blue][*][/bold bright_blue] Generating interactive attack graph webpage...")
    export_interactive_html(findings, metrics, html_path)
    console.print(f"[bold green][✓][/bold green] Interactive visualizer saved to: [u cyan]file:///{html_path.absolute().as_posix()}[/u cyan]")
    
    console.print(f"\n[bold green]=== Analysis Complete ===[/bold green]")
    console.print(f"Results saved to: [bold white]{out_dir.absolute()}[/bold white]\n")

def main() -> None:
    # Print banner automatically if help menu is requested
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        print_banner()

    parser = argparse.ArgumentParser(
        prog="lmr",
        description="[bold white]DESCRIPTION:[/bold white]\nAutomated pipeline for processing network captures, mapping lateral movement,\nand generating interactive attack graphs for Incident Response.",
        formatter_class=LMRFormatter,
        epilog=(
            "[bold bright_blue]EXAMPLES:[/bold bright_blue]\n"
            "  [dim]# Analyze a standard PCAP file[/dim]\n"
            "  [bold cyan]lmr analyze[/bold cyan] [yellow]evidence.pcap[/yellow] [bold cyan]--case[/bold cyan] [yellow]IR-001[/yellow]\n\n"
            "  [dim]# Analyze existing Zeek logs without rerunning Zeek[/dim]\n"
            "  [bold cyan]lmr analyze[/bold cyan] [bold cyan]--zeek-logs[/bold cyan] [yellow]./logs/[/yellow] [bold cyan]--case[/bold cyan] [yellow]APT-29[/yellow]\n\n"
            "  [dim]# Force Docker execution for Zeek isolation[/dim]\n"
            "  [bold cyan]lmr analyze[/bold cyan] [yellow]capture.pcapng[/yellow] [bold cyan]--case[/bold cyan] [yellow]WCCDC[/yellow] [bold cyan]--force-docker[/bold cyan]\n"
        )
    )
    
    parser.add_argument(
        "-v", "--version", action="version", version=f"[bold bright_cyan]LMR[/bold bright_cyan] version [white]{__version__}[/white]"
    )

    subparsers = parser.add_subparsers(
        title="[bold yellow]CORE MODULES[/bold yellow]",
        dest="command", 
        help="Select the operational mode",
        required=True
    )

    # --- DOCTOR COMMAND ---
    subparsers.add_parser(
        "doctor", 
        help="Run environment diagnostics (verifies Zeek & Docker integrations).",
        formatter_class=LMRFormatter
    )

    # --- ANALYZE COMMAND ---
    analyze_parser = subparsers.add_parser(
        "analyze", 
        aliases=["analyse"],
        help="Execute the full DFIR pipeline on a packet capture or Zeek log directory.",
        formatter_class=LMRFormatter,
        epilog=(
            "[bold bright_blue]OUTPUT:[/bold bright_blue]\n"
            "  Results are generated in the [bold white]out/<case_name>/[/bold white] directory, including:\n"
            "  - Interactive Attack Graph (report.html)\n"
            "  - Raw Findings (findings.json)\n"
            "  - Evidence CSVs for SIEM ingestion."
        )
    )
    
    # TARGET OPTIONS
    input_group = analyze_parser.add_argument_group("TARGET OPTIONS")
    input_group.add_argument(
        "capture", nargs="?", metavar="TARGET_PCAP", help="Path to the raw .pcap or .pcapng evidence file."
    )
    input_group.add_argument(
        "--zeek-logs", metavar="DIR_PATH", help="Path to a directory of pre-processed Zeek logs (skips packet parsing)."
    )
    
    # EXECUTION PARAMETERS
    config_group = analyze_parser.add_argument_group("EXECUTION PARAMETERS")
    config_group.add_argument(
        "-c", "--case", required=True, metavar="CASE_NAME", help="Mandatory case identifier (used for reporting and folder structure)."
    )
    config_group.add_argument(
        "--force-docker", action="store_true", help="Force Zeek to execute within a Docker container (ignores local installations)."
    )

    args = parser.parse_args()

    if args.command == "doctor":
        run_doctor()
    elif args.command in ["analyze", "analyse"]:
        run_analyze(args)

if __name__ == "__main__":
    main()