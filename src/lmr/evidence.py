"""
Evidence extraction module.

Generates precise Wireshark display filters and manages evidence extraction 
for lateral movement findings.
"""

from pathlib import Path
from typing import List

from lmr.schema import DetectionFinding


def generate_wireshark_filter(finding: DetectionFinding) -> str:
    """
    Constructs a precise Wireshark display filter based on the finding's IPs.
    """
    ip_filter = f"(ip.src == {finding.src_ip} and ip.dst == {finding.dst_ip}) or (ip.src == {finding.dst_ip} and ip.dst == {finding.src_ip})"
    
    if finding.title == "PsExec":
        return f"({ip_filter}) and (smb or smb2 or dcerpc)"
    
    # NEW: Filter specifically for WinRM traffic
    if finding.title == "WinRM Lateral Movement":
        return f"({ip_filter}) and (http and tcp.port in {{5985 5986}})"

    if finding.title == "WMI/DCOM Lateral Movement":
        return f"({ip_filter}) and (tcp.port == 135 or dcerpc)"

    if finding.title == "SMB Admin Share Lateral Movement":
        return f"({ip_filter}) and (tcp.port == 445 or smb or smb2)"
        
    return ip_filter


def export_evidence_filters(findings: List[DetectionFinding], out_dir: Path) -> None:
    """
    Creates an 'evidence' directory and writes reproducible Wireshark filters 
    for each finding so analysts can verify the behavior independently.
    """
    if not findings:
        return

    evidence_dir = out_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    
    filter_file = evidence_dir / "wireshark_filters.txt"
    
    with filter_file.open("w", encoding="utf-8") as f:
        f.write("LMR - Analyst Evidence Filters\n")
        f.write("==============================\n\n")
        
        for idx, finding in enumerate(findings, 1):
            ws_filter = generate_wireshark_filter(finding)
            
            # Security Patch: Prevent CRLF / Log Injection in our text reports
            safe_title = finding.title.replace("\r", "").replace("\n", " ")
            
            f.write(f"Finding #{idx}: {safe_title}\n")
            f.write(f"Rule ID: {finding.rule_id}\n")
            f.write(f"Filter: {ws_filter}\n")
            f.write("-" * 40 + "\n")