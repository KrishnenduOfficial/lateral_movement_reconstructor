"""
LMR Attack Graph & Interactive Webpage Simulation Script.
Generates an advanced multi-stage adversary campaign across 15 vectors 
to stress-test the HTML visualizer, layout spacing, and sidebar inspector.
"""

from pathlib import Path
from lmr.schema import DetectionFinding
from lmr.graph import build_attack_graph, analyze_graph_metrics
from lmr.report import export_interactive_html, export_findings

def generate_simulation_findings() -> list[DetectionFinding]:
    return [
        # Stage 1: Initial Compromise & Patient Zero Activity
        DetectionFinding(
            rule_id="LMR-SSH-001",
            title="SSH Brute Force / Initial Access",
            attack_ids=["T1021.004", "T1110"],
            confidence="High",
            src_ip="192.168.10.50",  # Patient Zero
            dst_ip="10.0.10.15",
            evidence_uids=["UID_SIM_001"],
            reason="External attacker leveraged SSH to breach the DMZ jump box.",
        ),
        DetectionFinding(
            rule_id="LMR-LINUX-002",
            title="Suspicious Cron Persistence",
            attack_ids=["T1053.003"],
            confidence="High",
            src_ip="10.0.10.15",
            dst_ip="10.0.10.15",
            evidence_uids=["UID_SIM_002"],
            reason="Adversary established persistence via root crontab modification.",
        ),

        # Stage 2: Lateral Spread via SSH & Linux Infrastructure
        DetectionFinding(
            rule_id="LMR-SSH-001",
            title="SSH Lateral Movement",
            attack_ids=["T1021.004"],
            confidence="High",
            src_ip="10.0.10.15",
            dst_ip="10.0.20.5",
            evidence_uids=["UID_SIM_003"],
            reason="Pivoted internally from DMZ jump box to internal web server.",
        ),
        DetectionFinding(
            rule_id="LMR-LINUX-001",
            title="Suspicious Sudo / Privilege Escalation",
            attack_ids=["T1548.003"],
            confidence="Medium",
            src_ip="10.0.20.5",
            dst_ip="10.0.20.5",
            evidence_uids=["UID_SIM_004"],
            reason="Unrestricted sudo execution observed on internal web server.",
        ),

# Stage 3: Windows Pivot & PsExec Execution Plane
        DetectionFinding(
            rule_id="LMR-PSEXEC-001",
            title="PsExec Lateral Movement (SVCINSTALL)",
            attack_ids=["T1021.002", "T1569.002"],
            confidence="High",
            src_ip="10.0.20.5",
            dst_ip="10.0.50.10",  # Target Hub (Domain Controller / File Server)
            evidence_uids=["UID_SIM_005"],
            reason="PISCES service dropped and executed via SMB administrative share.",
        ),
        DetectionFinding(
            rule_id="LMR-SMB-001",
            title="SMB Admin Share Lateral Movement",
            attack_ids=["T1021.002"],
            confidence="High",
            src_ip="10.0.20.5",
            dst_ip="10.0.50.20",  # Database Server
            evidence_uids=["UID_SIM_006"],
            reason="Administrative share access (C$) mounted dynamically.",
        ),

        # Stage 4: WMI, WinRM, and RDP Pivots
        DetectionFinding(
            rule_id="LMR-WMI-001",
            title="WMI Process Execution Lateral Movement",
            attack_ids=["T1047"],
            confidence="High",
            src_ip="10.0.50.10",
            dst_ip="10.0.50.20",
            evidence_uids=["UID_SIM_007"],
            reason="Remote process spawned via WMI Win32_Process class.",
        ),
        DetectionFinding(
            rule_id="LMR-WINRM-001",
            title="WinRM / PowerShell Remoting Session",
            attack_ids=["T1021.006"],
            confidence="Medium",
            src_ip="10.0.50.10",
            dst_ip="10.0.50.30",
            evidence_uids=["UID_SIM_008"],
            reason="WS-Management protocol session established for remote execution.",
        ),
        DetectionFinding(
            rule_id="LMR-RDP-001",
            title="RDP Lateral Movement Session",
            attack_ids=["T1021.001"],
            confidence="Medium",
            src_ip="10.0.50.10",
            dst_ip="10.0.50.40",
            evidence_uids=["UID_SIM_009"],
            reason="Remote Desktop Protocol connection initiated across internal subnet.",
        ),

        # Stage 5: Identity Abuse & Credential Access (Kerberos & NTLM)
        DetectionFinding(
            rule_id="LMR-KERB-001",
            title="Kerberoasting (Weak Cipher RC4 Downgrade)",
            attack_ids=["T1558.003"],
            confidence="High",
            src_ip="10.0.50.20",
            dst_ip="10.0.50.10",
            evidence_uids=["UID_SIM_010"],
            reason="RC4 cipher requested for TGS service ticket (MSSQLSvc/db01:1433).",
        ),
        DetectionFinding(
            rule_id="LMR-NTLM-001",
            title="NTLM Credential Spraying",
            attack_ids=["T1110.003"],
            confidence="High",
            src_ip="10.0.50.20",
            dst_ip="10.0.50.10",
            evidence_uids=["UID_SIM_011"],
            reason="High-volume NTLM authentication failures across >5 unique accounts.",
        ),
        DetectionFinding(
            rule_id="LMR-NTLM-002",
            title="NTLM Pass-the-Hash / Lateral Spread",
            attack_ids=["T1550.002"],
            confidence="Medium",
            src_ip="10.0.50.20",
            dst_ip="10.0.60.100",
            evidence_uids=["UID_SIM_012"],
            reason="Anomalous NTLM lateral spread across unique destination servers.",
        ),

        # Stage 6: Cross-Subnet Cascading Attacks
        DetectionFinding(
            rule_id="LMR-SSH-001",
            title="SSH Lateral Movement",
            attack_ids=["T1021.004"],
            confidence="High",
            src_ip="10.0.50.40",
            dst_ip="192.168.100.5",  # Isolated Backup Vault
            evidence_uids=["UID_SIM_013"],
            reason="Compromised host pivoting into secure management enclave.",
        ),
        DetectionFinding(
            rule_id="LMR-SMB-001",
            title="SMB Admin Share Lateral Movement",
            attack_ids=["T1021.002"],
            confidence="High",
            src_ip="192.168.100.5",
            dst_ip="192.168.100.10",
            evidence_uids=["UID_SIM_014"],
            reason="Admin share access within backup vault segment.",
        ),
    ]

def run_simulation() -> None:
    out_dir = Path("out") / "SIMULATED_CAMPAIGN"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("[*] Generating simulated multi-stage lateral movement findings...")
    findings = generate_simulation_findings()

    print("[*] Building attack graph and computing topology metrics...")
    graph = build_attack_graph(findings)
    metrics = analyze_graph_metrics(graph)

    print("[*] Exporting JSON, CSV, and interactive webpage dashboard...")
    export_findings(findings, out_dir)
    export_interactive_html(findings, metrics, out_dir / "report.html")

    print(f"\n[+] Simulation complete!")
    print(f"    - Total Hosts: {metrics['total_hosts']}")
    print(f"    - Total Pivots: {metrics['total_pivots']}")
    print(f"    - Patient Zero: {metrics['patient_zero_candidates']}")
    print(f"    - Target Hubs: {metrics['target_hubs']}")
    print(f"    - Interactive Report: {out_dir.absolute() / 'report.html'}\n")

if __name__ == "__main__":
    run_simulation()