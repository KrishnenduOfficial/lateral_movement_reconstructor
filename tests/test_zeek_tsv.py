"""
Unit tests for the Zeek TSV parser.
"""

from pathlib import Path
from lmr.parsers.zeek_tsv import parse_zeek_tsv


def test_parse_zeek_tsv_standard(tmp_path: Path) -> None:
    """Verifies that headers are skipped, fields are mapped dynamically, and unset fields become None."""
    dummy_log = tmp_path / "conn.log"
    
    # We use \t to strictly represent the tab characters
    log_content = (
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#empty_field\t(empty)\n"
        "#unset_field\t-\n"
        "#path\tconn\n"
        "#open\t2026-09-21-12-00-00\n"
        "#fields\tts\tuid\tid.orig_h\tduration\n"
        "#types\ttime\tstring\taddr\tinterval\n"
        "1600000000.000\tC12345\t192.168.1.10\t0.5\n"
        "1600000005.000\tC67890\t10.0.0.5\t-\n"
    )
    dummy_log.write_text(log_content, encoding="utf-8")

    # list() consumes the generator so we can inspect all results at once
    results = list(parse_zeek_tsv(dummy_log))

    # 1. Assert we only parsed the 2 data rows, ignoring the 8 header rows
    assert len(results) == 2

    # 2. Assert dynamic mapping works for the first row
    assert results[0]["uid"] == "C12345"
    assert results[0]["id.orig_h"] == "192.168.1.10"
    assert results[0]["duration"] == "0.5"

    # 3. Assert the unset character (-) correctly translates to Python's None type
    assert results[1]["duration"] is None