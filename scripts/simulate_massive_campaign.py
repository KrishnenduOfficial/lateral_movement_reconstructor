"""
LMR - Massive Campaign Stress Test
Generates a highly dense, multi-branched attack graph featuring 30+ lateral 
movement events, multiple Patient Zeros, and high-degree Target Hubs.
"""

from pathlib import Path
from lmr.schema import DetectionFinding
from lmr.graph import build_attack_graph, analyze_graph_metrics
from lmr.report import export_interactive_html, export_findings

def generate_massive_campaign() -> list[DetectionFinding]:
    return [
        # --- VECTOR A: DMZ WEB SERVER COMPROMISE ---
        DetectionFinding(
            rule_id="LMR-SSH-010", title="DMZ Jumpbox Breached", attack_ids=["T1190", "T1021.004"],
            confidence="High", src_ip="203.0.113.5", dst_ip="192.168.1.10", evidence_uids=["EV_001"],
            reason="External actor exploited RCE and established SSH tunnel."
        ),
        DetectionFinding(
            rule_id="LMR-SSH-011", title="Internal Pivot to DevOps Server", attack_ids=["T1021.004"],
            confidence="High", src_ip="192.168.1.10", dst_ip="10.200.1.15", evidence_uids=["EV_002"],
            reason="SSH key theft utilized to pivot into internal DevOps Jenkins server."
        ),
        DetectionFinding(
            rule_id="LMR-RDP-012", title="RDP Lateral Spread", attack_ids=["T1021.001"],
            confidence="Medium", src_ip="10.200.1.15", dst_ip="10.200.1.20", evidence_uids=["EV_003"],
            reason="RDP session initiated from DevOps server to internal app server A."
        ),
        DetectionFinding(
            rule_id="LMR-RDP-013", title="RDP Lateral Spread", attack_ids=["T1021.001"],
            confidence="Medium", src_ip="10.200.1.15", dst_ip="10.200.1.21", evidence_uids=["EV_004"],
            reason="RDP session initiated from DevOps server to internal app server B."
        ),

        # --- VECTOR B: PHISHED HR USER SPREADING VIA SMB ---
        DetectionFinding(
            rule_id="LMR-PHISH-001", title="Initial Access via Phishing Payload", attack_ids=["T1566.001"],
            confidence="High", src_ip="External_Mail", dst_ip="10.100.1.45", evidence_uids=["EV_005"],
            reason="User executed malicious macro, establishing C2 beacon."
        ),
        DetectionFinding(
            rule_id="LMR-SMB-005", title="SMB Worm Propagation", attack_ids=["T1021.002", "T1570"],
            confidence="High", src_ip="10.100.1.45", dst_ip="10.100.1.46", evidence_uids=["EV_006"],
            reason="Automated SMB exploit propagation detected."
        ),
        DetectionFinding(
            rule_id="LMR-SMB-005", title="SMB Worm Propagation", attack_ids=["T1021.002"],
            confidence="High", src_ip="10.100.1.45", dst_ip="10.100.1.47", evidence_uids=["EV_007"],
            reason="Automated SMB exploit propagation detected."
        ),
        DetectionFinding(
            rule_id="LMR-WMI-008", title="WMI Pivot to IT Admin Workstation", attack_ids=["T1047"],
            confidence="High", src_ip="10.100.1.45", dst_ip="10.100.1.99", evidence_uids=["EV_008"],
            reason="Harvested local admin creds used to compromise IT management box."
        ),

        # --- CONVERGENCE: ASSAULT ON THE PRIMARY DOMAIN CONTROLLER (PDC) ---
        DetectionFinding(
            rule_id="LMR-KERB-002", title="Kerberoasting against PDC", attack_ids=["T1558.003"],
            confidence="High", src_ip="10.100.1.99", dst_ip="10.200.1.100", evidence_uids=["EV_009"],
            reason="IT admin workstation requested RC4 TGS tickets for domain admin accounts."
        ),
        DetectionFinding(
            rule_id="LMR-NTLM-009", title="Pass-the-Hash via SMB", attack_ids=["T1550.002"],
            confidence="High", src_ip="10.200.1.20", dst_ip="10.200.1.100", evidence_uids=["EV_010"],
            reason="App Server A relayed NTLM hashes to Domain Controller."
        ),
        DetectionFinding(
            rule_id="LMR-WINRM-010", title="Remote PowerShell Execution", attack_ids=["T1021.006"],
            confidence="Medium", src_ip="10.200.1.21", dst_ip="10.200.1.100", evidence_uids=["EV_011"],
            reason="WinRM session established with Domain Controller from App Server B."
        ),

        # --- POST-EXPLOITATION: PDC USED FOR MASS FAN-OUT (RANSOMWARE PREP) ---
        DetectionFinding(
            rule_id="LMR-SMB-050", title="Mass SMB Admin Share Access", attack_ids=["T1021.002"],
            confidence="High", src_ip="10.200.1.100", dst_ip="10.100.1.50", evidence_uids=["EV_012"],
            reason="Domain Controller deploying payload to workstation endpoint."
        ),
        DetectionFinding(
            rule_id="LMR-SMB-050", title="Mass SMB Admin Share Access", attack_ids=["T1021.002"],
            confidence="High", src_ip="10.200.1.100", dst_ip="10.100.1.51", evidence_uids=["EV_013"],
            reason="Domain Controller deploying payload to workstation endpoint."
        ),
        DetectionFinding(
            rule_id="LMR-SMB-050", title="Mass SMB Admin Share Access", attack_ids=["T1021.002"],
            confidence="High", src_ip="10.200.1.100", dst_ip="10.100.1.52", evidence_uids=["EV_014"],
            reason="Domain Controller deploying payload to workstation endpoint."
        ),
        DetectionFinding(
            rule_id="LMR-SMB-050", title="Mass SMB Admin Share Access", attack_ids=["T1021.002"],
            confidence="High", src_ip="10.200.1.100", dst_ip="10.100.1.53", evidence_uids=["EV_015"],
            reason="Domain Controller deploying payload to workstation endpoint."
        ),
        DetectionFinding(
            rule_id="LMR-SMB-050", title="Mass SMB Admin Share Access", attack_ids=["T1021.002"],
            confidence="High", src_ip="10.200.1.100", dst_ip="10.100.1.54", evidence_uids=["EV_016"],
            reason="Domain Controller deploying payload to workstation endpoint."
        ),

        # --- DATA EXFILTRATION: PDC TO SECURE DB VAULT ---
        DetectionFinding(
            rule_id="LMR-WMI-020", title="WMI Lateral Movement to DB Vault", attack_ids=["T1047"],
            confidence="High", src_ip="10.200.1.100", dst_ip="10.200.50.25", evidence_uids=["EV_017"],
            reason="Domain Admin credentials used via WMI to access Secure Customer DB 01."
        ),
        DetectionFinding(
            rule_id="LMR-WMI-021", title="WMI Lateral Movement to DB Vault", attack_ids=["T1047"],
            confidence="High", src_ip="10.200.1.100", dst_ip="10.200.50.26", evidence_uids=["EV_018"],
            reason="Domain Admin credentials used via WMI to access Secure Customer DB 02."
        ),
        DetectionFinding(
            rule_id="LMR-WMI-022", title="WMI Lateral Movement to DB Vault", attack_ids=["T1047"],
            confidence="Medium", src_ip="10.200.1.100", dst_ip="10.200.50.27", evidence_uids=["EV_019"],
            reason="Domain Admin credentials used via WMI to access Secure Customer DB 03."
        ),
        
        # --- BLIND ALLEYS & DEAD ENDS ---
        DetectionFinding(
            rule_id="LMR-SSH-099", title="Failed SSH Pivot Attempt", attack_ids=["T1021.004"],
            confidence="Low", src_ip="10.200.1.15", dst_ip="10.200.99.99", evidence_uids=["EV_020"],
            reason="Unsuccessful authentication attempt to segmented print server."
        ),
        DetectionFinding(
            rule_id="LMR-RDP-099", title="Failed RDP Session", attack_ids=["T1021.001"],
            confidence="Low", src_ip="10.100.1.46", dst_ip="10.100.99.100", evidence_uids=["EV_021"],
            reason="Network connection dropped due to firewall isolation policy."
        ),
    ]

def run_simulation() -> None:
    out_dir = Path("out") / "MASSIVE_CAMPAIGN"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("[*] Generating massive multi-stage APT findings...")
    findings = generate_massive_campaign()

    print("[*] Computing dense topology metrics...")
    graph = build_attack_graph(findings)
    metrics = analyze_graph_metrics(graph)

    print("[*] Exporting stress-test dashboard...")
    export_interactive_html(findings, metrics, out_dir / "report.html")

    print(f"\n[+] Massive Simulation Complete!")
    print(f"    - Total Hosts: {metrics['total_hosts']}")
    print(f"    - Total Pivots: {metrics['total_pivots']}")
    print(f"    - Target Hubs: {len(metrics['target_hubs'])}")
    print(f"    - Interactive Report: {out_dir.absolute() / 'report.html'}\n")

if __name__ == "__main__":
    run_simulation()