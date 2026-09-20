"""
Input validation for packet captures.

Inspects file headers via magic numbers rather than relying on file extensions,
ensuring files are valid pcap or pcapng captures before invoking external tools.
"""

from enum import Enum
from pathlib import Path


class CaptureFormat(str, Enum):
    PCAP = "pcap"
    PCAPNG = "pcapng"


class UnsupportedFileFormatError(ValueError):
    """Raised when an input file is not a supported capture format."""
    pass


# Magic byte signatures
# Classic PCAP magic variants (4 bytes)
PCAP_MICRO_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MICRO_BE = b"\xa1\xb2\xc3\xd4"
PCAP_NANO_LE = b"\x4d\x3c\xb2\xa1"
PCAP_NANO_BE = b"\xa1\xb2\x3c\x4d"
PCAP_MAGICS = {PCAP_MICRO_LE, PCAP_MICRO_BE, PCAP_NANO_LE, PCAP_NANO_BE}

# PCAPNG Section Header Block magic (4 bytes)
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# Common non-capture signatures
GZIP_MAGIC = b"\x1f\x8b"
ZIP_MAGIC = b"\x50\x4b\x03\x04"


def inspect_capture_file(path: Path) -> CaptureFormat:
    """
    Validates that a target path points to a readable, valid pcap or pcapng file.

    Args:
        path: Pathlib Path pointing to the target capture.

    Returns:
        CaptureFormat: The detected format (PCAP or PCAPNG).

    Raises:
        FileNotFoundError: If the file does not exist.
        UnsupportedFileFormatError: If the file is empty, corrupted, or unsupported.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Capture file not found: {path}")

    # Read the first 4 bytes to identify the file format
    with path.open("rb") as f:
        header = f.read(4)

    if len(header) < 4:
        raise UnsupportedFileFormatError(
            f"File '{path.name}' is too small to be a valid capture (empty or truncated)."
        )

    if header in PCAP_MAGICS:
        return CaptureFormat.PCAP

    if header == PCAPNG_MAGIC:
        return CaptureFormat.PCAPNG

    # Diagnosing specific common problematic files
    if header.startswith(GZIP_MAGIC):
        raise UnsupportedFileFormatError(
            f"File '{path.name}' is a Gzip-compressed archive. "
            "Zeek cannot read .gz captures directly. Please decompress the file first."
        )

    if header == ZIP_MAGIC:
        raise UnsupportedFileFormatError(
            f"File '{path.name}' is a ZIP archive. Please extract the capture file first."
        )

    if header.startswith(b"<"):
        raise UnsupportedFileFormatError(
            f"File '{path.name}' begins with an HTML tag ('<'). "
            "It is likely an error webpage downloaded instead of a capture file."
        )

    # Generic unrecognized header
    hex_header = header.hex()
    raise UnsupportedFileFormatError(
        f"File '{path.name}' is not a recognized capture format (Header hex: {hex_header})."
    )