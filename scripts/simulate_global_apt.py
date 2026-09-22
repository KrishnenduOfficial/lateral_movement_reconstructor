"""
LMR - Operation Midnight Forge (Global APT Stress Test)
Simulates a multi-region, highly complex supply chain and insider threat compromise.
Designed to test D3.js physics constraints, dynamic Blast Radius parsing, and MITRE heatmap widgets.
"""

from pathlib import Path
from lmr.schema import DetectionFinding
from lmr.graph import build_attack_graph, analyze_graph_metrics
from lmr.report import export_interactive_html
from lmr.report import export_interactive_html, export_findings # Fallback if export_findings is used

def generate_global_campaign() -> list[DetectionFinding]:
    return [
        # --- PHASE 1: DUAL-VECTOR INITIAL COMPROMISE (EMEA & APAC) ---
        DetectionFinding(
            rule_id="LMR-PHISH-001", title="Spearphishing Attachment Executed", attack_ids=["T1566.001", "T1204.002"],
            confidence="High", src_ip="External_Mail", dst_ip="10.50.1.100", evidence_uids=["EV_GL_001"],
            reason="EMEA HR workstation compromised via malicious PDF macro payload dropping a C2 beacon."
        ),
        DetectionFinding(
            rule_id="LMR-VULN-002", title="Public-Facing App Exploit (Zero-Day)", attack_ids=["T1190"],
            confidence="High", src_ip="203.0.113.10", dst_ip="10.80.5.15", evidence_uids=["EV_GL_002"],
            reason="APAC edge VPN appliance exploited via unauthenticated RCE, establishing SSH reverse tunnel."
        ),

        # --- PHASE 2: EMEA LATERAL EXPANSION (SMB & WMI) ---
        DetectionFinding(
            rule_id="LMR-SMB-010", title="SMB Admin Share Enumeration", attack_ids=["T1021.002"],
            confidence="Medium", src_ip="10.50.1.100", dst_ip="10.50.1.105", evidence_uids=["EV_GL_003"],
            reason="Compromised EMEA host testing local administrative shares across sales subnet."
        ),
        DetectionFinding(
            rule_id="LMR-WMI-011", title="WMI Remote Process Execution", attack_ids=["T1047"],
            confidence="High", src_ip="10.50.1.100", dst_ip="10.50.2.50", evidence_uids=["EV_GL_004"],
            reason="Lateral pivot into EMEA management enclave utilizing harvested local admin credentials."
        ),

        # --- PHASE 3: APAC LATERAL EXPANSION & PERSISTENCE (SSH & CRON) ---
        DetectionFinding(
            rule_id="LMR-SSH-020", title="SSH Key Hijacking", attack_ids=["T1021.004", "T1552.004"],
            confidence="High", src_ip="10.80.5.15", dst_ip="10.80.5.30", evidence_uids=["EV_GL_005"],
            reason="Stolen SSH keys from VPN appliance used to pivot into APAC internal DevOps server."
        ),
        DetectionFinding(
            rule_id="LMR-CRON-021", title="Malicious Cron Job Installed", attack_ids=["T1053.003"],
            confidence="Low", src_ip="10.80.5.30", dst_ip="10.80.5.30", evidence_uids=["EV_GL_006"],
            reason="Adversary scheduled persistent reverse shell callback on DevOps server (Low Confidence Anomaly)."
        ),
        DetectionFinding(
            rule_id="LMR-WINRM-022", title="WinRM PowerShell Pivot", attack_ids=["T1021.006"],
            confidence="Medium", src_ip="10.80.5.30", dst_ip="10.80.10.100", evidence_uids=["EV_GL_007"],
            reason="Remote PowerShell session established from Linux DevOps server to APAC Windows Build Node."
        ),

        # --- PHASE 4: GLOBAL CONVERGENCE TO US-CENTRAL DATACENTER HUB ---
        DetectionFinding(
            rule_id="LMR-WMI-030", title="Cross-Region WMI Pivot", attack_ids=["T1047"],
            confidence="High", src_ip="10.50.2.50", dst_ip="10.10.10.5", evidence_uids=["EV_GL_008"],
            reason="EMEA management node pivoted across global WAN to US-Central Identity Server."
        ),
        DetectionFinding(
            rule_id="LMR-RDP-031", title="Cross-Region RDP Tunneling", attack_ids=["T1021.001"],
            confidence="High", src_ip="10.80.10.100", dst_ip="10.10.10.5", evidence_uids=["EV_GL_009"],
            reason="APAC Build Node established unauthorized RDP session to US-Central Identity Server."
        ),

        # --- PHASE 5: IDENTITY ABUSE AT THE CORE (KERBEROS & NTLM) ---
        DetectionFinding(
            rule_id="LMR-KERB-040", title="Targeted Kerberoasting", attack_ids=["T1558.003"],
            confidence="High", src_ip="10.10.10.5", dst_ip="10.10.10.10", evidence_uids=["EV_GL_010"],
            reason="Identity Server requesting RC4 service tickets against Primary Domain Controller (PDC)."
        ),
        DetectionFinding(
            rule_id="LMR-NTLM-041", title="Overpass-the-Hash", attack_ids=["T1550.002"],
            confidence="High", src_ip="10.10.10.5", dst_ip="10.10.10.10", evidence_uids=["EV_GL_011"],
            reason="PDC compromised using cracked NTLM hashes; full domain takeover achieved."
        ),

        # --- PHASE 6: RANSOMWARE FAN-OUT & DATA EXFILTRATION ---
        # Massive fan-out from PDC to various critical DBs and endpoints
        DetectionFinding(rule_id="LMR-SMB-050", title="Mass Payload Deployment", attack_ids=["T1570", "T1021.002"], confidence="High", src_ip="10.10.10.10", dst_ip="10.10.20.50", evidence_uids=["EV_GL_012"], reason="PDC utilizing SMB Admin Shares to deploy ransomware payload to Secure DB 1."),
        DetectionFinding(rule_id="LMR-SMB-050", title="Mass Payload Deployment", attack_ids=["T1570", "T1021.002"], confidence="High", src_ip="10.10.10.10", dst_ip="10.10.20.51", evidence_uids=["EV_GL_013"], reason="PDC utilizing SMB Admin Shares to deploy ransomware payload to Secure DB 2."),
        DetectionFinding(rule_id="LMR-SMB-050", title="Mass Payload Deployment", attack_ids=["T1570", "T1021.002"], confidence="High", src_ip="10.10.10.10", dst_ip="10.10.20.52", evidence_uids=["EV_GL_014"], reason="PDC utilizing SMB Admin Shares to deploy ransomware payload to Secure DB 3."),
        DetectionFinding(rule_id="LMR-WMI-051", title="Mass Payload Deployment via WMI", attack_ids=["T1047"], confidence="Medium", src_ip="10.10.10.10", dst_ip="10.100.1.10", evidence_uids=["EV_GL_015"], reason="PDC forcing payload execution on US-East Endpoint 1."),
        DetectionFinding(rule_id="LMR-WMI-051", title="Mass Payload Deployment via WMI", attack_ids=["T1047"], confidence="Medium", src_ip="10.10.10.10", dst_ip="10.100.1.11", evidence_uids=["EV_GL_016"], reason="PDC forcing payload execution on US-East Endpoint 2."),
        DetectionFinding(rule_id="LMR-WMI-051", title="Mass Payload Deployment via WMI", attack_ids=["T1047"], confidence="Low", src_ip="10.10.10.10", dst_ip="10.100.1.12", evidence_uids=["EV_GL_017"], reason="PDC forcing payload execution on US-East Endpoint 3."),
        
        # Dead end / Failed attempt
        DetectionFinding(
            rule_id="LMR-RDP-060", title="Blocked RDP Pivot", attack_ids=["T1021.001"],
            confidence="Low", src_ip="10.10.20.50", dst_ip="192.168.200.5", evidence_uids=["EV_GL_018"],
            reason="Attempted lateral movement to isolated backup vault blocked by zero-trust firewall."
        ),
    ]

def run_simulation() -> None:
    out_dir = Path("out") / "GLOBAL_APT_CAMPAIGN"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("[*] Initializing Operation Midnight Forge (Global APT Stress Test)...")
    findings = generate_global_campaign()

    print("[*] Computing complex topology matrices and Blast Radius variables...")
    graph = build_attack_graph(findings)
    metrics = analyze_graph_metrics(graph)

    print("[*] Compiling Enterprise Dashboard and pre-warming D3.js physics...")
    try:
        export_findings(findings, out_dir) # If your original script had this, keep it.
    except NameError:
        pass # Handle if export_findings is not imported/defined in your schema
        
    export_interactive_html(findings, metrics, out_dir / "report.html")

    print(f"\n[+] Massive Simulation Complete!")
    print(f"    - Total Hosts Compromised: {metrics['total_hosts']}")
    print(f"    - Attack Vectors Mapped: {metrics['total_pivots']}")
    print(f"    - Target Hubs Identified: {len(metrics['target_hubs'])}")
    print(f"    - Patient Zeros Isolated: {len(metrics['patient_zero_candidates'])}")
    print(f"    - Launch Dashboard: {out_dir.absolute() / 'report.html'}\n")

if __name__ == "__main__":
    run_simulation()