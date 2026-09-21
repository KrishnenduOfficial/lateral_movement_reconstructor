"""
Zeek execution module.

Discovers and runs Zeek (either via a local installation or Docker container)
against a target packet capture, outputting logs into an isolated directory.
"""

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from lmr.input_check import inspect_capture_file


class ZeekExecutionError(RuntimeError):
    """Raised when Zeek fails during execution."""
    pass


@dataclass
class ZeekResult:
    """Stores execution metrics and output directory details."""
    log_dir: Path
    generated_logs: List[str]
    success: bool
    stderr: str


def find_zeek_binary() -> Optional[str]:
    """Checks whether 'zeek' is installed directly on the host system."""
    return shutil.which("zeek")


def find_docker_binary() -> Optional[str]:
    """Checks whether 'docker' is available on the host system."""
    return shutil.which("docker")


def run_zeek(
    capture_path: Path,
    output_dir: Path,
    timeout_seconds: int = 300,
    force_docker: bool = False,
) -> ZeekResult:
    """
    Executes Zeek on a capture file, generating logs in output_dir.

    Args:
        capture_path: Path to the target .pcap or .pcapng.
        output_dir: Folder where Zeek should write its generated logs.
        timeout_seconds: Maximum allowed runtime before timing out.
        force_docker: Run via Docker even if a local binary is found.

    Returns:
        ZeekResult with execution details and discovered logs.

    Raises:
        FileNotFoundError: If capture does not exist.
        UnsupportedFileFormatError: If capture magic bytes are invalid.
        ZeekExecutionError: If neither Zeek nor Docker is available, or if execution fails.
    """
    inspect_capture_file(capture_path)

    capture_path = capture_path.resolve()
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    local_zeek = find_zeek_binary()

    if local_zeek and not force_docker:
        cmd = [local_zeek, "-C", "-r", str(capture_path)]
        cwd = output_dir
    else:
        if not find_docker_binary():
            raise ZeekExecutionError(
                "Neither local 'zeek' binary nor 'docker' command was found. "
                "Install Docker or run 'lmr doctor' for environment guidance."
            )

        # Mount capture dir as read-only /pcap, output dir as /work
        capture_dir = capture_path.parent
        internal_capture = f"/pcap/{capture_path.name}"

        cmd = [
            "docker",
            "run",
            "--rm",
            "-v", f"{capture_dir}:/pcap:ro",
            "-v", f"{output_dir}:/work",
            "-w", "/work",
            "zeek/zeek",
            "zeek",
            "-C",
            "-r", internal_capture,
        ]
        cwd = output_dir

    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ZeekExecutionError(
            f"Zeek analysis timed out after {timeout_seconds} seconds."
        ) from exc
    except Exception as exc:
        raise ZeekExecutionError(f"Failed to execute Zeek: {exc}") from exc

    if proc.returncode != 0 and not any(output_dir.glob("*.log")):
        raise ZeekExecutionError(
            f"Zeek exited with code {proc.returncode}.\nStderr: {proc.stderr.strip()}"
        )

    generated = sorted([p.name for p in output_dir.glob("*.log")])

    return ZeekResult(
        log_dir=output_dir,
        generated_logs=generated,
        success=True,
        stderr=proc.stderr,
    )