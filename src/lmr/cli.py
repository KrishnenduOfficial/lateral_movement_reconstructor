import argparse
import shutil
import sys

from lmr import __version__


def run_doctor() -> None:
    """Inspects the host environment for required dependencies."""
    print(f"lmr v{__version__} System Check\n" + "-" * 40)

    # 1. Check Python
    print(f"Python Version: {sys.version.split()[0]}")

    # 2. Check Local Zeek
    zeek_path = shutil.which("zeek")
    if zeek_path:
        print(f"[OK] Local Zeek found: {zeek_path}")
    else:
        print("[INFO] Local Zeek not found (Normal for Windows users).")

    # 3. Check Docker
    docker_path = shutil.which("docker")
    if docker_path:
        print(f"[OK] Docker found: {docker_path}")
    else:
        print("[!] Docker not found.")

    print("-" * 40)
    
    # Provide Analyst Next Steps
    if docker_path or zeek_path:
        print("[READY] System meets the requirements to analyze packet captures.")
    else:
        print(
            "[ERROR] Neither Zeek nor Docker is installed.\n"
            "To analyze PCAPs, you must install Docker Desktop (Windows/macOS)\n"
            "or install Zeek locally (Linux).\n"
            "Download Docker: https://www.docker.com/products/docker-desktop/"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="lmr",
        description="Lateral Movement Reconstructor (lmr) - Automated DFIR network analysis.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    # Create subcommands (doctor, analyze)
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: lmr doctor
    subparsers.add_parser(
        "doctor", help="Check system dependencies (Zeek, Docker) and provide guidance."
    )

    # Command: lmr analyze (Placeholder for Step 5e)
    subparsers.add_parser(
        "analyze", help="Analyze a packet capture or existing Zeek logs."
    )

    args = parser.parse_args()

    # Route to the correct function based on the user's command
    if args.command == "doctor":
        run_doctor()
    elif args.command == "analyze":
        print("Analyze pipeline will be wired up in Step 5e.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()