"""
Unit tests for the Zeek runner module.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from lmr.zeek_runner import ZeekExecutionError, run_zeek


def test_zeek_missing_dependencies(tmp_path: Path) -> None:
    """Raises ZeekExecutionError if neither Zeek nor Docker is installed."""
    dummy_pcap = tmp_path / "valid.pcap"
    dummy_pcap.write_bytes(b"\xd4\xc3\xb2\xa1empty_test_bytes")
    out_dir = tmp_path / "out"

    with patch("lmr.zeek_runner.find_zeek_binary", return_value=None), \
         patch("lmr.zeek_runner.find_docker_binary", return_value=None):
        with pytest.raises(ZeekExecutionError, match="Neither local 'zeek' binary nor 'docker'"):
            run_zeek(dummy_pcap, out_dir)


def test_zeek_local_execution_success(tmp_path: Path) -> None:
    """Verifies that local Zeek runs and captures generated logs."""
    dummy_pcap = tmp_path / "valid.pcap"
    dummy_pcap.write_bytes(b"\xd4\xc3\xb2\xa1empty_test_bytes")
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    # Simulate Zeek creating a conn.log
    (out_dir / "conn.log").write_text("#separator \\x09\n", encoding="utf-8")

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stderr = ""

    with patch("lmr.zeek_runner.find_zeek_binary", return_value="/usr/bin/zeek"), \
         patch("subprocess.run", return_value=mock_proc) as mock_run:
        result = run_zeek(dummy_pcap, out_dir)

        assert result.success is True
        assert "conn.log" in result.generated_logs
        mock_run.assert_called_once()
        cmd_called = mock_run.call_args[0][0]
        assert cmd_called[0] == "/usr/bin/zeek"
        assert "-C" in cmd_called
        assert "-r" in cmd_called