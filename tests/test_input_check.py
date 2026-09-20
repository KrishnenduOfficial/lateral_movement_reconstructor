"""
Tests for packet capture input validation.

Verifies detection of PCAP and PCAPNG formats by magic bytes,
and ensures helpful errors are raised for invalid or unsupported inputs.
"""

from pathlib import Path
import pytest

from lmr.input_check import (
    CaptureFormat,
    UnsupportedFileFormatError,
    inspect_capture_file,
)


def test_valid_pcap_microsecond_le(tmp_path: Path) -> None:
    """A standard little-endian microsecond PCAP should be recognized."""
    capture = tmp_path / "test.pcap"
    # First 4 bytes: d4 c3 b2 a1, followed by dummy packet data
    capture.write_bytes(b"\xd4\xc3\xb2\xa1extra_packet_data")

    result = inspect_capture_file(capture)
    assert result == CaptureFormat.PCAP


def test_valid_pcapng(tmp_path: Path) -> None:
    """A PCAPNG file (0a 0d 0d 0a) should be recognized."""
    capture = tmp_path / "test.pcapng"
    capture.write_bytes(b"\x0a\x0d\x0d\x0aextra_section_header")

    result = inspect_capture_file(capture)
    assert result == CaptureFormat.PCAPNG


def test_reject_gzip_file(tmp_path: Path) -> None:
    """Gzip files (1f 8b) must fail with a helpful decompression message."""
    gz_file = tmp_path / "traffic.pcap.gz"
    gz_file.write_bytes(b"\x1f\x8b\x08\x00dummy_compressed_bytes")

    with pytest.raises(UnsupportedFileFormatError, match="Gzip-compressed"):
        inspect_capture_file(gz_file)


def test_reject_zip_file(tmp_path: Path) -> None:
    """ZIP files (50 4b 03 04) must fail prompting the user to extract."""
    zip_file = tmp_path / "bundle.zip"
    zip_file.write_bytes(b"\x50\x4b\x03\x04dummy_zip_content")

    with pytest.raises(UnsupportedFileFormatError, match="ZIP archive"):
        inspect_capture_file(zip_file)


def test_reject_html_file(tmp_path: Path) -> None:
    """HTML files (e.g. failed curl downloads) must be rejected."""
    html_file = tmp_path / "error.pcap"
    html_file.write_bytes(b"<html><head><title>404 Not Found</title></head></html>")

    with pytest.raises(UnsupportedFileFormatError, match="HTML tag"):
        inspect_capture_file(html_file)


def test_reject_empty_file(tmp_path: Path) -> None:
    """An empty or truncated file (< 4 bytes) must be rejected."""
    empty_file = tmp_path / "empty.pcap"
    empty_file.write_bytes(b"\x00\x01")  # only 2 bytes

    with pytest.raises(UnsupportedFileFormatError, match="too small"):
        inspect_capture_file(empty_file)


def test_missing_file(tmp_path: Path) -> None:
    """A nonexistent path must raise FileNotFoundError."""
    missing = tmp_path / "does_not_exist.pcap"

    with pytest.raises(FileNotFoundError):
        inspect_capture_file(missing)