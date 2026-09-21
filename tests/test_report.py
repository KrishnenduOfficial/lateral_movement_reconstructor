"""
Unit tests for report generation.
Utilizes pytest.mark.parametrize to rigorously fuzz the exporter against 
malicious payloads, boundary conditions, and structural edge cases.
"""

import csv
import json
import pytest
from pathlib import Path

from lmr.schema import DetectionFinding
from lmr.report import export_findings


# A matrix of hostile inputs that typically break poorly written parsers
NASTY_PAYLOADS = [
    ("basic_string", "Standard output"),
    ("csv_injection_cmd", "=cmd|' /C calc'!A0"),
    ("csv_injection_sum", "@SUM(1+1)"),
    ("csv_injection_minus", "-2+3"),
    ("comma_storm", ",,,,,,,,,,,"),
    ("quote_storm", '"""\'\'\'"""\'\'\''),
    ("newline_crlf", "Line 1\r\nLine 2"),
    ("newline_lf", "Line 1\nLine 2"),
    ("tab_storm", "\t\t\t\t\t"),
    ("xss_basic", "<script>alert('XSS')</script>"),
    ("xss_img", "<img src=x onerror=alert(1)>"),
    ("sqli_auth", "admin' OR '1'='1'--"),
    ("sqli_stacked", "'; DROP TABLE findings;--"),
    ("path_traversal", "../../../../etc/passwd"),
    ("null_byte", "Text\x00with\x00nulls"),
    ("unicode_zalgo", "T̵̹̫̉̚h̷̺̎ì̶͝s̵̜͝ ̷͚̊ḯ̶͙s̵̨͋ ̸̤̾Z̵̭͝a̵̹͝l̵̟̐g̵̬̿ō̸̢"),
    ("unicode_emoji", "🚀🚨💀👾"),
    ("unicode_rtl", "‮test of right to left text"),
    ("json_breaker_braces", "{{{}}}"),
    ("json_breaker_brackets", "[[[]]]"),
    ("json_breaker_escape", "\\\\\\\\\\"),
    ("buffer_stretch", "A" * 50000), # 50k character string
    ("empty_string", ""),
    ("whitespace_only", "   \n  \t  "),
    ("boolean_string", "False"),
]

@pytest.mark.parametrize("payload_name, payload_value", NASTY_PAYLOADS, ids=[payload[0] for payload in NASTY_PAYLOADS])
def test_export_fuzzing_resilience(tmp_path: Path, payload_name: str, payload_value: str) -> None:
    """
    [Insane] Fuzzes the exporter by injecting hostile payloads into the text fields.
    Validates that Python's csv and json libraries properly escape the payloads 
    without corrupting the file structure or dropping data.
    """
    findings = [
        DetectionFinding(
            rule_id=f"F-{payload_name}",
            title=payload_value,
            attack_ids=["T1021.002"],
            confidence="High",
            src_ip="10.0.0.5",
            dst_ip="10.0.0.20",
            evidence_uids=["C1"],
            reason=payload_value
        )
    ]
    
    export_findings(findings, tmp_path)
    
    # 1. Validate JSON Integrity
    with (tmp_path / "findings.json").open("r", encoding="utf-8") as f:
        data = json.load(f)
        
    assert data[0]["title"] == payload_value
    assert data[0]["reason"] == payload_value

    # 2. Validate CSV Integrity
    with (tmp_path / "findings.csv").open("r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
        
    assert len(rows) == 1
    assert rows[0]["title"] == payload_value
    assert rows[0]["reason"] == payload_value


def test_export_empty_findings_list(tmp_path: Path) -> None:
    """[Medium] Validates that passing an empty list exits gracefully."""
    export_findings([], tmp_path)
    assert not (tmp_path / "findings.json").exists()
    assert not (tmp_path / "findings.csv").exists()


def test_export_missing_output_directory(tmp_path: Path) -> None:
    """[Medium] Validates the exact exception raised if the output directory is missing."""
    missing_dir = tmp_path / "does_not_exist"
    finding = DetectionFinding("F-001", "Title", [], "High", "1.1.1.1", "2.2.2.2", [], "Reason")
    
    with pytest.raises(FileNotFoundError):
        export_findings([finding], missing_dir)


def test_export_csv_list_reassembly(tmp_path: Path) -> None:
    """[Hard] Validates that lists flattened to strings in CSV can be perfectly reconstructed."""
    original_attack_ids = ["T1021.002", "T1569.002"]
    original_evidence_uids = ["C1", "C2", "C3"]
    
    findings = [
        DetectionFinding(
            "F-001", "Title", original_attack_ids, "High", "1.1.1.1", "2.2.2.2", 
            original_evidence_uids, "Reason"
        )
    ]
    export_findings(findings, tmp_path)
    
    with (tmp_path / "findings.csv").open("r", encoding="utf-8", newline="") as f:
        row = list(csv.DictReader(f))[0]
    
    # Ensure our comma-join logic works perfectly and can be reversed by an analyst
    assert row["attack_ids"].split(",") == original_attack_ids
    assert row["evidence_uids"].split(",") == original_evidence_uids


def test_export_strict_json_schema_compliance(tmp_path: Path) -> None:
    """[Hard] Validates that the JSON output strictly mirrors the Dataclass fields."""
    finding = DetectionFinding("F-001", "Title", [], "High", "1.1.1.1", "2.2.2.2", [], "Reason")
    export_findings([finding], tmp_path)
    
    with (tmp_path / "findings.json").open("r", encoding="utf-8") as f:
        data = json.load(f)
    
    exported_keys = set(data[0].keys())
    dataclass_keys = set(finding.__dataclass_fields__.keys())
    
    assert exported_keys == dataclass_keys