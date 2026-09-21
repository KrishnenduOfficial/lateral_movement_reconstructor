"""
Unit tests for the evidence extraction module.
Includes 30 distinct tests covering Medium, Hard, and Insane edge cases
for Wireshark filter generation and text file integrity.
"""

import pytest
from pathlib import Path

from lmr.schema import DetectionFinding
from lmr.evidence import generate_wireshark_filter, export_evidence_filters


# ==========================================
# MEDIUM: Standard Operational Scenarios
# ==========================================

def test_generate_wireshark_filter_psexec() -> None:
    """[Medium] Validates that PsExec findings get the specific SMB/DCERPC protocol filters."""
    finding = DetectionFinding(
        rule_id="F-001", title="PsExec", attack_ids=["T1021.002"],
        confidence="High", src_ip="10.0.0.5", dst_ip="10.0.0.20", evidence_uids=[], reason="Test"
    )
    expected_ip = "(ip.src == 10.0.0.5 and ip.dst == 10.0.0.20) or (ip.src == 10.0.0.20 and ip.dst == 10.0.0.5)"
    assert generate_wireshark_filter(finding) == f"({expected_ip}) and (smb or smb2 or dcerpc)"


def test_generate_wireshark_filter_generic() -> None:
    """[Medium] Validates that unknown or generic findings gracefully fall back to just the IP filter."""
    finding = DetectionFinding(
        rule_id="F-002", title="Unknown Attack", attack_ids=[],
        confidence="Low", src_ip="192.168.1.5", dst_ip="192.168.1.100", evidence_uids=[], reason="Test"
    )
    expected_ip = "(ip.src == 192.168.1.5 and ip.dst == 192.168.1.100) or (ip.src == 192.168.1.100 and ip.dst == 192.168.1.5)"
    assert generate_wireshark_filter(finding) == expected_ip


def test_export_evidence_filters_empty(tmp_path: Path) -> None:
    """[Medium] Validates that no evidence folder is created if there are no findings."""
    export_evidence_filters([], tmp_path)
    assert not (tmp_path / "evidence").exists()


# ==========================================
# HARD: IP Address & Hostname Fuzzing
# ==========================================

NASTY_IPS = [
    ("ipv6_standard", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
    ("ipv6_compressed", "::1"),
    ("ipv4_mapped_ipv6", "::ffff:192.0.2.128"),
    ("dns_hostname", "WIN-DC01.corp.local"),
    ("mac_address", "00:1A:2B:3C:4D:5E"),
    ("spaces_padding", "   10.0.0.1   "),
    ("xss_payload", "<script>alert(1)</script>"),
    ("sqli_payload", "1.1.1.1' OR 1=1--"),
    ("cmd_injection", "; rm -rf /"),
    ("unicode_rtl", "‮10.0.0.1"),
    ("zalgo_text", "1̸0̸.0.0.1"),
    ("empty_string", ""),
    ("special_chars", "!@#$%^&*()"),
    ("quotes", "\"10.0.0.1\""),
    ("newline_injection", "10.0.0.1\n10.0.0.2"),
    ("emoji", "🚨.🚨.🚨.🚨"),
    ("null_byte", "10.0.0.1\x00"),
    ("json_format", '{"ip": "10.0.0.1"}'),
    ("csv_injection", "=CMD|' /C CALC'!A0"),
    ("path_traversal", "../../../../etc/passwd"),
    ("buffer_stretch", "1" * 10000)  # 10,000 character string
]

@pytest.mark.parametrize("payload_name, payload_value", NASTY_IPS, ids=[p[0] for p in NASTY_IPS])
def test_wireshark_filter_ip_fuzzing(payload_name: str, payload_value: str) -> None:
    """
    [Hard] Injects 21 hostile/malformed data payloads into the IP fields to ensure
    the string formatter never crashes and properly embeds exactly what it is given.
    """
    finding = DetectionFinding(
        rule_id=f"F-{payload_name}", title="Generic", attack_ids=[], confidence="High",
        src_ip=payload_value, dst_ip="2.2.2.2", evidence_uids=[], reason="Fuzzing"
    )
    
    result = generate_wireshark_filter(finding)
    
    assert f"ip.src == {payload_value}" in result
    assert f"ip.dst == {payload_value}" in result


# ==========================================
# INSANE: Exporter Text File Integrity
# ==========================================

NASTY_TITLES = [
    ("title_newline", "PsExec\nNew Line Attack\r\nThird Line"),
    ("title_xss", "<img src=x onerror=alert(1)>"),
    ("title_unicode", "PsExec 🚀 Атака"),
    ("title_format_string", "%s%p%x%d"),
    ("title_buffer", "A" * 50000)
]

@pytest.mark.parametrize("payload_name, payload_value", NASTY_TITLES, ids=[p[0] for p in NASTY_TITLES])
def test_export_evidence_title_fuzzing(tmp_path: Path, payload_name: str, payload_value: str) -> None:
    """
    [Insane] Validates that hostile text titles containing newlines or extreme lengths 
    do not crash the file writer, and verifies that CRLF injection is sanitized.
    """
    findings = [
        DetectionFinding(
            rule_id="F-001", title=payload_value, attack_ids=[], confidence="High",
            src_ip="1.1.1.1", dst_ip="2.2.2.2", evidence_uids=[], reason="Fuzz"
        )
    ]
    
    export_evidence_filters(findings, tmp_path)
    
    filter_file = tmp_path / "evidence" / "wireshark_filters.txt"
    assert filter_file.exists()
    
    content = filter_file.read_text(encoding="utf-8")
    
    # We expect the engine to sanitize CRLF characters to prevent log injection
    expected_safe_title = payload_value.replace("\r", "").replace("\n", " ")
    
    assert expected_safe_title in content
    assert "Rule ID: F-001" in content


def test_export_massive_volume_evidence(tmp_path: Path) -> None:
    """
    [Insane] Stress tests the evidence exporter by writing 10,000 distinct findings 
    into the text file to check memory stability and I/O performance.
    """
    massive_findings = [
        DetectionFinding(
            rule_id=f"F-{i}", title=f"Attack {i}", attack_ids=[], confidence="Low",
            src_ip=f"10.0.0.{i%255}", dst_ip="2.2.2.2", evidence_uids=[], reason="Noise"
        ) for i in range(10000)
    ]
    
    export_evidence_filters(massive_findings, tmp_path)
    
    filter_file = tmp_path / "evidence" / "wireshark_filters.txt"
    assert filter_file.exists()
    
    content = filter_file.read_text(encoding="utf-8")
    assert "Finding #10000: Attack 9999" in content
    assert "Rule ID: F-9999" in content