"""
Report generation module.

Exports in-memory DetectionFinding objects to standard, machine-readable
formats (JSON and CSV) for SIEM ingestion and analyst review.
"""

import csv
import json
from dataclasses import asdict
from pathlib import Path
from typing import List
from lmr.evidence import generate_wireshark_filter
from lmr.schema import DetectionFinding

from lmr.schema import DetectionFinding


def export_findings(findings: List[DetectionFinding], out_dir: Path) -> None:
    """
    Writes detection findings to findings.json and findings.csv inside the output directory.
    """
    if not findings:
        return

    json_path = out_dir / "findings.json"
    csv_path = out_dir / "findings.csv"

    # Convert dataclasses to standard Python dictionaries
    findings_dicts = [asdict(f) for f in findings]

    # 1. Export JSON (Machine-readable for SIEMs/SOAR)
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(findings_dicts, f, indent=4)

    # 2. Export CSV (Human-readable for Excel / Timeline Explorer)
    if findings_dicts:
        # Extract the column headers from the keys of the first finding
        headers = list(findings_dicts[0].keys())
        
        with csv_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            
            for row in findings_dicts:
                # Convert lists (like evidence_uids) to strings so they fit in a CSV cell
                csv_row = {
                    k: (",".join(v) if isinstance(v, list) else v) 
                    for k, v in row.items()
                }
                writer.writerow(csv_row)

def export_wireshark_script(findings, output_path) -> None:
    """Combines all unique Wireshark filters into a single shell script."""
    filters = set()
    for f in findings:
        wf = generate_wireshark_filter(f)
        if wf:
            filters.add(wf)

    combined_filter = " or ".join(f"({flt})" for flt in sorted(filters)) if filters else "frame"

    with open(output_path, "w", encoding="utf-8") as fp:
        fp.write("#!/bin/sh\n")
        fp.write("# Auto-generated LMR Wireshark Tshark display filter\n")
        fp.write(f'WIRESHARK_FILTER="{combined_filter}"\n')
        fp.write('echo "Combined filter: $WIRESHARK_FILTER"\n')

def compute_blast_radius_summary(findings: List[DetectionFinding], graph_metrics: dict) -> dict:
    """Dynamically evaluates blast radius, subnet traversal, and protocol exposure."""
    subnets = set()
    protocols = set()
    high_conf_count = 0

    for f in findings:
        for ip in [str(f.src_ip), str(f.dst_ip)]:
            parts = ip.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                subnets.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
            elif "External" in ip or "mail" in ip.lower():
                subnets.add("Perimeter / Ext-Enclave")

        if f.confidence == "High":
            high_conf_count += 1

        title_lower = (f.title + " " + f.rule_id).lower()
        for proto in ["SMB", "WMI", "RDP", "WinRM", "SSH", "Kerberos", "NTLM", "Phishing", "Cron"]:
            if proto.lower() in title_lower:
                protocols.add(proto)

    total_hosts = graph_metrics.get("total_hosts", len(findings))
    target_hubs = graph_metrics.get("target_hubs", [])
    patient_zeros = graph_metrics.get("patient_zero_candidates", [])

    if len(target_hubs) >= 3 or total_hosts >= 15:
        threat_level = "CRITICAL (TIER 1)"
        threat_color = "var(--sev-critical)"
        depth_assessment = "Systemic Enterprise Breach: Multi-hop adversary traversal traversing critical core segments."
    elif len(target_hubs) >= 1 or total_hosts >= 5:
        threat_level = "HIGH (TIER 2)"
        threat_color = "var(--sev-high)"
        depth_assessment = "Elevated Internal Propagation: Core infrastructure accessed with high privilege execution."
    else:
        threat_level = "MODERATE (TIER 3)"
        threat_color = "var(--sev-medium)"
        depth_assessment = "Contained Pivot Threat: Movements limited to perimeter and adjacent endpoints."

    return {
        "threat_level": threat_level,
        "threat_color": threat_color,
        "depth_assessment": depth_assessment,
        "subnets_count": len(subnets),
        "subnets_list": sorted(list(subnets)),
        "protocols_list": sorted(list(protocols)) if protocols else ["Administrative SMB", "Remote RPC"],
        "high_conf_count": high_conf_count,
        "target_hubs_count": len(target_hubs),
        "target_hubs_str": ", ".join(target_hubs) if target_hubs else "None",
        "patient_zeros_str": ", ".join(patient_zeros) if patient_zeros else "None"
    }

def export_interactive_html(findings: List[DetectionFinding], graph_metrics: dict, output_path: Path) -> None:
    nodes_map = {}
    edges_list = []
    tactic_counts: dict[str, int] = {}

    patient_zero_set = set(graph_metrics.get("patient_zero_candidates", []))
    target_hubs_set = set(graph_metrics.get("target_hubs", []))
    blast = compute_blast_radius_summary(findings, graph_metrics)

    for f in findings:
        for tid in f.attack_ids:
            tactic_counts[tid] = tactic_counts.get(tid, 0) + 1
            
    max_tactic_count = max(tactic_counts.values()) if tactic_counts else 1
    
    heatmap_html = ""
    for tactic, count in sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True):
        intensity = count / max_tactic_count
        heatmap_html += f"""
        <div class="flex justify-between items-center p-2 rounded border border-[var(--border-subtle)]" style="background: linear-gradient(90deg, var(--grad-heat-low) 0%, rgba(139, 92, 246, {intensity * 0.5}) 100%);">
            <code class="text-[var(--text-secondary)] text-xs font-mono">{tactic}</code>
            <span class="text-[var(--text-primary)] font-semibold text-xs tabular-nums">{count}</span>
        </div>
        """

    for f in findings:
        src = str(f.src_ip)
        dst = str(f.dst_ip)

        if src not in nodes_map:
            is_pz = src in patient_zero_set
            nodes_map[src] = {
                "id": src,
                "label": src,
                "type": "Patient Zero" if is_pz else "Source Host",
                "color": "var(--sev-critical)" if is_pz else "var(--sev-medium)",
                "is_pz": is_pz,
                "scale": 1.0 
            }

        if dst not in nodes_map:
            is_hub = dst in target_hubs_set
            nodes_map[dst] = {
                "id": dst,
                "label": dst,
                "type": "Target Hub" if is_hub else "Destination",
                "color": "var(--accent-500)" if is_hub else "var(--sev-info)",
                "is_pz": False,
                "scale": 1.0 
            }

        edges_list.append({
            "source": src,
            "target": dst,
            "title": f.title,
            "confidence": f.confidence,
            "reason": f.reason,
            "attack_ids": f.attack_ids
        })

    subnet_badges_html = "".join([f'<span class="px-2 py-0.5 rounded text-[11px] font-mono bg-[var(--bg-void)] border border-[var(--border-subtle)] text-[var(--accent-300)] mr-1 mb-1 inline-block">{s}</span>' for s in blast["subnets_list"]])
    protocol_badges_html = "".join([f'<span class="px-2 py-0.5 rounded text-[11px] font-mono bg-[var(--bg-void)] border border-[var(--border-subtle)] text-[var(--sev-low)] mr-1 mb-1 inline-block">{p}</span>' for p in blast["protocols_list"]])

    nodes_json = json.dumps(list(nodes_map.values()))
    edges_json = json.dumps(edges_list)
    findings_json = json.dumps([asdict(f) for f in findings])
    tactics_labels = json.dumps(list(tactic_counts.keys()))
    tactics_data = json.dumps(list(tactic_counts.values()))

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>LMR // Threat Intelligence & Lateral Recon</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-void:      #000000;
      --bg-panel:     #08080c;
      --bg-card:      #0e0d16;
      --bg-card-2:    #161324;
      --border-subtle:#231d3b;
      --border-glow:  #8b5cf6;
      --accent-300:   #c4b5fd;
      --accent-500:   #8b5cf6;
      --accent-600:   #7c3aed;
      --accent-glow:  rgba(139, 92, 246, 0.6);
      --sev-critical: #ff0055;
      --sev-high:     #ff6600;
      --sev-medium:   #ffb703;
      --sev-low:      #00f5d4;
      --sev-info:     #00e5ff;
      --text-primary:   #ffffff;
      --text-secondary: #cbd5e1;
      --text-muted:     #64748b;
      --grad-panel:     linear-gradient(160deg, #120e24 0%, #08080c 100%);
      --grad-heat-low:  #0a0816;
    }}
    
    body {{
      font-family: 'Inter', system-ui, sans-serif;
      background-color: var(--bg-void);
      color: var(--text-primary);
      margin: 0; padding: 0;
    }}

    .font-mono {{ font-family: 'JetBrains Mono', monospace; }}
    .tabular-nums {{ font-variant-numeric: tabular-nums; }}
    .micro-label {{ font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); }}

    ::-webkit-scrollbar {{ width: 5px; height: 5px; }}
    ::-webkit-scrollbar-track {{ background: transparent; }}
    ::-webkit-scrollbar-thumb {{ background: var(--border-subtle); border-radius: 3px; }}
    ::-webkit-scrollbar-thumb:hover {{ background: var(--accent-500); }}

    .soc-card {{
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 10px;
      box-shadow: 0 1px 0 rgba(255,255,255,0.05) inset, 0 8px 30px rgba(0,0,0,0.8);
    }}
    
    .soc-finding-card {{
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      padding: 14px;
      margin-bottom: 12px;
      box-shadow: 0 4px 15px rgba(0,0,0,0.5);
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
    }}
    .soc-finding-card:hover {{
      background: var(--bg-card-2);
      transform: translateY(-2px);
      border-color: var(--border-glow);
      box-shadow: 0 0 20px var(--accent-glow), 0 8px 20px rgba(0,0,0,0.6);
    }}

    .node-group {{ cursor: grab; outline: none; }}
    .node-group:active {{ cursor: grabbing; }}
    .node-group.selected .node-bg {{ stroke: var(--border-glow); stroke-width: 3px; }}
    .node-group.selected {{ filter: drop-shadow(0 0 20px var(--accent-glow)); }}

    .resize-btn {{ fill: var(--bg-void); stroke: var(--border-subtle); stroke-width: 1.5; }}

    #canvas-container {{ background-color: #000000; overflow: hidden; }}
    
    .fullscreen-mode {{
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      width: 100vw !important;
      height: 100vh !important;
      z-index: 9999 !important;
      border-radius: 0 !important;
      border: none !important;
    }}
  </style>
</head>
<body class="min-h-screen flex flex-col">

  <header class="bg-[var(--bg-panel)] border-b border-[var(--border-subtle)] px-8 py-4 flex justify-between items-center z-50 sticky top-0 shadow-2xl">
    <div class="flex items-center space-x-4">
      <div class="bg-[var(--bg-card)] border border-[var(--accent-600)] text-[var(--accent-300)] shadow-[0_0_15px_rgba(139,92,246,0.3)] px-3 py-1.5 rounded font-bold text-xs tracking-widest">
        LMR // FORENSICS
      </div>
      <div>
        <h1 class="text-sm font-semibold tracking-wide text-white">Lateral Movement Intelligence Report</h1>
      </div>
    </div>
    <div class="flex items-center space-x-3 text-xs">
      <div class="flex items-center space-x-2 bg-[var(--bg-card)] border border-[var(--border-subtle)] px-3 py-1.5 rounded-lg">
        <span class="w-2 h-2 rounded-full bg-[var(--sev-low)] animate-pulse"></span>
        <span class="text-[var(--text-secondary)] font-mono">SYSTEM: ACTIVE</span>
      </div>
    </div>
  </header>

  <main class="flex-1 max-w-[1600px] w-full mx-auto p-6 space-y-6 overflow-y-auto">
    
    <div class="grid grid-cols-1 md:grid-cols-4 gap-5">
      <div class="soc-card p-5 relative overflow-hidden border-t-2 border-t-[var(--accent-300)]" style="background: var(--grad-panel);">
        <div class="micro-label mb-2 text-[var(--accent-300)] flex items-center gap-2">
           <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
           Total Pivots Detected
        </div>
        <div class="text-[34px] font-bold tabular-nums text-[var(--text-primary)] leading-tight mt-1">{graph_metrics.get("total_pivots", 0)}</div>
      </div>
      <div class="soc-card p-5 relative overflow-hidden border-t-2 border-t-[var(--accent-500)]" style="background: var(--grad-panel);">
        <div class="micro-label mb-2 text-[var(--accent-500)] flex items-center gap-2">
           <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
           Compromised Assets
        </div>
        <div class="text-[34px] font-bold tabular-nums text-[var(--text-primary)] leading-tight mt-1">{graph_metrics.get("total_hosts", 0)}</div>
      </div>
      <div class="soc-card p-5 relative overflow-hidden border-t-2 border-t-[var(--sev-critical)]" style="background: var(--grad-panel);">
        <div class="micro-label mb-2 text-[var(--sev-critical)] flex items-center gap-2">
           <svg width="14" height="14" viewBox="0 0 24 24"><path d="M12 2L22 12L12 22L2 12Z" fill="currentColor"/></svg>
           Patient Zero Hub
        </div>
        <div class="text-[17px] font-bold font-mono text-white truncate mt-4">{blast["patient_zeros_str"]}</div>
      </div>
      <div class="soc-card p-5 relative overflow-hidden border-t-2 border-t-[var(--sev-high)]" style="background: var(--grad-panel);">
        <div class="micro-label mb-2 text-[var(--sev-high)] flex items-center gap-2">
           <svg width="14" height="14" viewBox="0 0 24 24"><path d="M12 2l10 18H2z" fill="currentColor"/></svg>
           Target Hubs
        </div>
        <div class="text-[34px] font-bold tabular-nums text-[var(--text-primary)] leading-tight mt-1">{blast["target_hubs_count"]}</div>
      </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <div class="lg:col-span-2 soc-card p-6 flex flex-col justify-between" style="background: linear-gradient(160deg, rgba(255,0,85,0.05) 0%, var(--bg-card) 100%);">
        <div>
          <div class="flex items-center justify-between pb-3 border-b border-[var(--border-subtle)]">
            <h2 class="text-sm font-bold tracking-wider uppercase text-[var(--sev-critical)] flex items-center gap-2">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
              Blast Radius Assessment
            </h2>
            <div class="flex items-center gap-2">
              <span class="micro-label px-2.5 py-1 rounded border border-[var(--border-subtle)] bg-[var(--bg-void)]" style="color: {blast['threat_color']};">
                {blast["threat_level"]}
              </span>
            </div>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
            <div class="bg-[var(--bg-panel)] border border-[var(--border-subtle)] p-4 rounded-lg shadow-inner flex flex-col justify-between">
              <div>
                <div class="flex justify-between items-center mb-2">
                  <span class="micro-label text-[var(--text-secondary)]">Subnet Infiltration Scope</span>
                  <span class="text-xs font-mono text-[var(--accent-300)] font-bold">{blast["subnets_count"]} Enclaves</span>
                </div>
                <p class="text-[12px] text-slate-300 mb-3">{blast["depth_assessment"]}</p>
              </div>
              <div class="max-h-[60px] overflow-y-auto pr-1">
                {subnet_badges_html}
              </div>
            </div>

            <div class="bg-[var(--bg-panel)] border border-[var(--border-subtle)] p-4 rounded-lg shadow-inner flex flex-col justify-between">
              <div>
                <div class="flex justify-between items-center mb-2">
                  <span class="micro-label text-[var(--text-secondary)]">Vector & Exposure Profile</span>
                  <span class="text-xs font-mono text-[var(--sev-critical)] font-bold">{blast["high_conf_count"]} High-Impact</span>
                </div>
                <p class="text-[12px] text-slate-300 mb-3">Compromised Targets: <span class="font-mono text-white text-[11px]">{blast["target_hubs_str"]}</span></p>
              </div>
              <div class="max-h-[60px] overflow-y-auto pr-1">
                {protocol_badges_html}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="soc-card p-6 flex flex-col">
        <h2 class="mb-4 flex items-center justify-between text-sm font-bold text-white">
          MITRE ATT&CK 
          <span class="micro-label bg-[var(--bg-panel)] border border-[var(--border-subtle)] px-2 py-1 rounded">Vector Frequency</span>
        </h2>
        <div class="flex-1 relative flex items-center justify-center pt-2 min-h-[160px]">
          <canvas id="mitreChart"></canvas>
        </div>
      </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6" style="min-height: 650px;">
      
      <div class="lg:col-span-2 soc-card flex flex-col overflow-hidden relative border border-[var(--border-subtle)]">
        <div class="px-6 py-4 border-b border-[var(--border-subtle)] bg-[var(--bg-card)] flex justify-between items-center z-10 shadow-md">
          <h2 class="text-sm font-bold text-white">Live Topographical Entity Graph</h2>
          <span class="micro-label text-[var(--text-muted)]">Scale nodes and build structural trees</span>
        </div>
        
        <div id="canvas-container" class="flex-1 relative w-full h-[600px] cursor-grab">
          <div class="absolute bottom-5 left-5 flex gap-2 z-10 bg-[var(--bg-card)] p-2 rounded-lg border border-[var(--border-subtle)] shadow-[0_10px_30px_rgba(0,0,0,0.8)]">
            <button class="w-9 h-9 rounded-md bg-[var(--bg-panel)] text-[var(--text-secondary)] hover:bg-[var(--accent-600)] hover:text-white border border-[var(--border-subtle)] flex items-center justify-center transition-all" onclick="zoomIn()" title="Zoom In Canvas">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            </button>
            <button class="w-9 h-9 rounded-md bg-[var(--bg-panel)] text-[var(--text-secondary)] hover:bg-[var(--accent-600)] hover:text-white border border-[var(--border-subtle)] flex items-center justify-center transition-all" onclick="zoomOut()" title="Zoom Out Canvas">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="5" y1="12" x2="19" y2="12"/></svg>
            </button>
            
            <div class="w-px h-6 bg-[var(--border-subtle)] my-auto mx-1"></div>
            
            <button class="w-9 h-9 rounded-md bg-[var(--bg-panel)] text-[var(--text-secondary)] hover:bg-[var(--accent-600)] hover:text-white border border-[var(--border-subtle)] flex items-center justify-center transition-all" onclick="fitToScreen()" title="Fit Canvas to Screen (Justify)">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 14v6h6M20 10V4h-6M10 20H4M14 4h6M4 4l5 5M20 20l-5-5M20 4l-5 5M4 20l5-5"/></svg>
            </button>
            <button class="w-9 h-9 rounded-md bg-[var(--bg-panel)] text-[var(--text-secondary)] hover:bg-[var(--accent-600)] hover:text-white border border-[var(--border-subtle)] flex items-center justify-center transition-all" onclick="resetLayout()" title="Explode & Reset Layout">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
            </button>
            
            <div class="w-px h-6 bg-[var(--border-subtle)] my-auto mx-1"></div>
            
            <button class="w-9 h-9 rounded-md bg-[var(--bg-panel)] text-[var(--text-secondary)] hover:bg-[var(--accent-600)] hover:text-white border border-[var(--border-subtle)] flex items-center justify-center transition-all" onclick="toggleFullscreen()" title="Toggle Fullscreen Canvas">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"/></svg>
            </button>
          </div>
        </div>
      </div>

      <div class="soc-card flex flex-col overflow-hidden">
        <div class="px-6 py-4 border-b border-[var(--border-subtle)] bg-[var(--bg-card)] shadow-md">
          <h2 class="text-sm font-bold text-white">Triage Inspector</h2>
        </div>
        <div id="sidebar-content" class="p-5 overflow-y-auto flex-1 bg-[var(--bg-panel)]">
          <div class="text-[var(--text-muted)] text-center italic mt-24 text-[12px] bg-[var(--bg-void)] border border-[var(--border-subtle)] p-6 rounded-lg">
            Select any entity on the tactical map to inspect forensic telemetry, ATT&CK mapping, and lateral depth.
          </div>
        </div>
      </div>

    </div>
  </main>

  <script>
    const ctxChart = document.getElementById('mitreChart').getContext('2d');
    new Chart(ctxChart, {{
      type: 'doughnut',
      data: {{
        labels: {tactics_labels},
        datasets: [{{
          data: {tactics_data},
          backgroundColor: ['#8b5cf6', '#c4b5fd', '#ff0055', '#ff6600', '#00e5ff', '#00f5d4'],
          borderColor: '#0e0d16',
          borderWidth: 2,
        }}]
      }},
      options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{
          legend: {{ position: 'right', labels: {{ color: '#a1a1b8', font: {{ family: 'Inter', size: 11 }} }} }}
        }},
        cutout: '75%'
      }}
    }});

    const nodesData = {nodes_json};
    const edgesData = {edges_json};
    const rawFindings = {findings_json};

    function getSeverityShape(conf) {{
      if(conf === 'High') return '<svg width="12" height="12" viewBox="0 0 24 24"><path d="M12 2L22 20H2Z" fill="currentColor"/></svg>';
      if(conf === 'Medium') return '<svg width="12" height="12" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2" fill="currentColor"/></svg>';
      return '<svg width="12" height="12" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="currentColor"/></svg>';
    }}
    function getSeverityColor(conf) {{
      if(conf === 'High') return 'var(--sev-high)';
      if(conf === 'Medium') return 'var(--sev-medium)';
      return 'var(--sev-low)';
    }}

    const containerNode = document.getElementById("canvas-container");
    const container = d3.select("#canvas-container");
    let width = container.node().clientWidth;
    let height = container.node().clientHeight;

    const svg = container.append("svg")
        .attr("width", "100%")
        .attr("height", "100%");

    const defs = svg.append("defs");
    const pattern = defs.append("pattern")
        .attr("id", "gridPattern")
        .attr("width", 40)
        .attr("height", 40)
        .attr("patternUnits", "userSpaceOnUse");
    pattern.append("circle")
        .attr("cx", 2).attr("cy", 2).attr("r", 1.5).attr("fill", "rgba(139, 92, 246, 0.15)");

    ['High', 'Medium'].forEach(conf => {{
        defs.append("marker")
            .attr("id", `arrow-${{conf}}`)
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 9)
            .attr("refY", 0)
            .attr("markerWidth", 6)
            .attr("markerHeight", 6)
            .attr("orient", "auto")
            .append("path")
            .attr("fill", conf === 'High' ? 'var(--sev-critical)' : 'var(--sev-medium)')
            .attr("d", "M0,-5L10,0L0,5");
    }});

    const g = svg.append("g");
    const zoomBehavior = d3.zoom()
        .scaleExtent([0.1, 4])
        .on("zoom", (e) => {{
            g.attr("transform", e.transform);
        }});
    
    svg.call(zoomBehavior);
    svg.on("dblclick.zoom", null);

    g.append("rect")
        .attr("x", -5000).attr("y", -5000)
        .attr("width", 10000).attr("height", 10000)
        .attr("fill", "url(#gridPattern)");

    // STATIC PRE-COMPUTED PHYSICS: The simulation runs silently, then stops completely.
    let simulation = d3.forceSimulation(nodesData)
        .force("link", d3.forceLink(edgesData).id(d => d.id).distance(130))
        .force("charge", d3.forceManyBody().strength(-1500))
        .force("collide", d3.forceCollide().radius(50))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .stop(); // Stop immediately so it doesn't animate on screen

    // Synchronously pre-warm the graph so nodes are perfectly arranged before rendering
    for (let i = 0; i < 300; ++i) simulation.tick();

    const link = g.append("g")
        .selectAll("line")
        .data(edgesData)
        .join("line")
        .attr("stroke-width", 2)
        .attr("stroke", d => d.confidence === 'High' ? 'rgba(255, 0, 85, 0.6)' : 'rgba(255, 183, 3, 0.5)')
        .attr("marker-end", d => `url(#arrow-${{d.confidence}})`);

    // MANUAL UPDATE FUNCTION: Redraws nodes instantly without physics drift
    function updatePositions() {{
        link.attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => {{
                const dx = d.target.x - d.source.x;
                const dy = d.target.y - d.source.y;
                const dist = Math.hypot(dx, dy) || 1;
                const targetRadius = 37 * (d.target.scale || 1);
                return d.target.x - (dx / dist) * targetRadius;
            }})
            .attr("y2", d => {{
                const dx = d.target.x - d.source.x;
                const dy = d.target.y - d.source.y;
                const dist = Math.hypot(dx, dy) || 1;
                const targetRadius = 37 * (d.target.scale || 1);
                return d.target.y - (dy / dist) * targetRadius;
            }});
            
        node.attr("transform", d => "translate(" + d.x + "," + d.y + ") scale(" + (d.scale || 1) + ")");
    }}

    const node = g.append("g")
        .selectAll("g")
        .data(nodesData)
        .join("g")
        .attr("class", "node-group")
        .call(d3.drag()
            .on("start", (e, d) => {{
                // REMOVED simulation.restart() to prevent all other nodes from waking up and floating
                d.fx = d.x; d.fy = d.y;
                d3.selectAll('.node-group').classed("selected", false);
                d3.select(e.sourceEvent.target.parentNode).classed("selected", true);
            }})
            .on("drag", (e, d) => {{
                // Instantly move only the selected node
                d.fx = e.x; d.fy = e.y;
                d.x = e.x; d.y = e.y;
                updatePositions(); // Manually redraw graph
            }})
            .on("end", (e, d) => {{
                d.fx = e.x; d.fy = e.y; // Keep it pinned permanently
            }})
        )
        .on("click", (e, d) => {{
            d3.selectAll('.node-group').classed("selected", false);
            d3.select(e.currentTarget).classed("selected", true);
            updateSidebar(d);
        }});

    // Draw Vector Nodes
    node.append("circle").attr("class", "node-bg").attr("r", 30).attr("fill", "#0e0d16").attr("stroke", "var(--border-subtle)").attr("stroke-width", 2);
    node.append("circle").attr("r", 25).attr("fill", d => d.color).attr("opacity", 0.15);

    node.each(function(d) {{
        const el = d3.select(this);
        if (d.is_pz) {{
            el.append("path").attr("d", "M 0 -12 L 14 8 L -14 8 Z").attr("fill", "none").attr("stroke", d.color).attr("stroke-width", 2);
            el.append("circle").attr("cx", 0).attr("cy", 2).attr("r", 2).attr("fill", d.color);
        }} else {{
            el.append("rect").attr("x", -10).attr("y", -11).attr("width", 20).attr("height", 8).attr("rx", 2).attr("fill", "none").attr("stroke", d.color).attr("stroke-width", 2);
            el.append("rect").attr("x", -10).attr("y", 3).attr("width", 20).attr("height", 8).attr("rx", 2).attr("fill", "none").attr("stroke", d.color).attr("stroke-width", 2);
        }}
    }});

    node.append("rect")
        .attr("x", d => -(d.id.length * 7.5 + 20) / 2)
        .attr("y", 38)
        .attr("width", d => d.id.length * 7.5 + 20)
        .attr("height", 24)
        .attr("rx", 6)
        .attr("fill", "#000000")
        .attr("stroke", d => d.color)
        .attr("stroke-width", 1.5)
        .attr("class", "pill-bg");

    node.append("text")
        .attr("x", 0)
        .attr("y", 54)
        .attr("text-anchor", "middle")
        .attr("fill", "#ffffff")
        .attr("font-family", "'JetBrains Mono', monospace")
        .attr("font-size", "12px")
        .attr("font-weight", "bold")
        .text(d => d.id);

    // STATIC NODE SCALING CONTROLS
    node.each(function(d) {{
        const el = d3.select(this);
        const controls = el.append("g")
            .attr("class", "node-resize-controls")
            .attr("transform", "translate(34, -26)");

        const plusBtn = controls.append("g").style("cursor", "pointer")
            .on("click", (e, d) => {{
                e.stopPropagation();
                // Unlimited scale up
                d.scale = (d.scale || 1.0) + 0.25; 
                updatePositions(); // Manually redraw graph
            }});
        plusBtn.append("rect").attr("class", "resize-btn").attr("width", 16).attr("height", 16).attr("rx", 3);
        plusBtn.append("text").attr("x", 8).attr("y", 12).attr("text-anchor", "middle").attr("fill", "var(--text-secondary)").attr("font-weight", "bold").attr("font-size", "12px").text("+");

        const minusBtn = controls.append("g").style("cursor", "pointer").attr("transform", "translate(0, 20)")
            .on("click", (e, d) => {{
                e.stopPropagation();
                // Limited scale down to 0.5x minimum
                d.scale = Math.max((d.scale || 1.0) - 0.25, 0.5);
                updatePositions(); // Manually redraw graph
            }});
        minusBtn.append("rect").attr("class", "resize-btn").attr("width", 16).attr("height", 16).attr("rx", 3);
        minusBtn.append("text").attr("x", 8).attr("y", 11).attr("text-anchor", "middle").attr("fill", "var(--text-secondary)").attr("font-weight", "bold").attr("font-size", "12px").text("-");
    }});

    // Render positions immediately on load using the pre-computed coordinates
    updatePositions();

    function fitToScreen() {{
        const bounds = g.node().getBBox();
        if (bounds.width === 0 || bounds.height === 0) return;
        
        width = containerNode.clientWidth;
        height = containerNode.clientHeight;

        const dx = bounds.width;
        const dy = bounds.height;
        const x = bounds.x + dx / 2;
        const y = bounds.y + dy / 2;
        
        const scale = Math.max(0.2, Math.min(3.5, 0.85 / Math.max(dx / width, dy / height)));
        const translate = [width / 2 - scale * x, height / 2 - scale * y];
        
        svg.transition().duration(850).call(
            zoomBehavior.transform,
            d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale)
        );
    }}

    setTimeout(fitToScreen, 100);
    window.addEventListener('resize', () => {{
        width = containerNode.clientWidth;
        height = containerNode.clientHeight;
    }});

    function zoomIn() {{ svg.transition().call(zoomBehavior.scaleBy, 1.3); }}
    function zoomOut() {{ svg.transition().call(zoomBehavior.scaleBy, 1/1.3); }}
    
    function resetLayout() {{
        d3.selectAll(".node-group").classed("selected", false);
        nodesData.forEach(d => {{ d.fx = null; d.fy = null; d.scale = 1.0; }});
        
        // Temporarily turn simulation back on to re-explode graph
        simulation.alpha(1).restart();
        
        // Force simulation to compute completely off-screen
        for (let i = 0; i < 300; ++i) simulation.tick();
        
        // Stop simulation permanently again
        simulation.stop();
        
        // Redraw
        updatePositions();
        setTimeout(fitToScreen, 100);
        
        document.getElementById("sidebar-content").innerHTML = '<div class="text-[var(--text-muted)] text-center italic mt-24 text-[12px] bg-[var(--bg-void)] border border-[var(--border-subtle)] p-6 rounded-lg">Select any entity on the tactical map to inspect forensic telemetry, ATT&CK mapping, and lateral depth.</div>';
    }}

    function toggleFullscreen() {{
        containerNode.classList.toggle('fullscreen-mode');
        width = containerNode.clientWidth;
        height = containerNode.clientHeight;
        setTimeout(fitToScreen, 100);
    }}

    document.addEventListener('keydown', (e) => {{
        if (e.key === 'Escape' && containerNode.classList.contains('fullscreen-mode')) {{
            toggleFullscreen();
        }}
    }});

    function updateSidebar(clicked) {{
      const detailsDiv = document.getElementById("sidebar-content");
      let related = rawFindings.filter(f => f.src_ip === clicked.id || f.dst_ip === clicked.id);

      let html = '<div class="mb-4"><h3 class="text-[14px] font-bold text-white mb-1 flex items-center gap-2">Entity Profile: <span class="bg-[var(--bg-void)] px-1.5 py-0.5 rounded border border-[var(--border-glow)] font-mono text-[var(--accent-300)]">' + clicked.id + '</span></h3>' +
                 '<p class="text-[12px] text-[var(--text-muted)]">Role: <span class="text-[var(--text-secondary)]">' + clicked.type + '</span> &bull; Vectors: ' + related.length + '</p></div><hr class="border-[var(--border-subtle)] mb-4">';
      
      related.forEach(f => {{
        let tagsHtml = f.attack_ids.map(t => '<span class="bg-[var(--bg-void)] border border-[var(--border-subtle)] text-[var(--text-secondary)] px-1.5 py-0.5 rounded text-[10px] font-mono mr-1 shadow-sm">' + t + '</span>').join('');
        let sevColor = getSeverityColor(f.confidence);
        let sevShape = getSeverityShape(f.confidence);
        
        html += '<div class="soc-finding-card border-l-[3px]" style="border-left-color: ' + sevColor + ';">' +
                '<h4 class="text-[13px] font-semibold text-white mb-1.5 leading-snug">' + f.title + '</h4>' +
                '<div class="mb-2 font-mono text-[10.5px] text-[var(--text-secondary)] bg-[var(--bg-void)] px-2 py-1 rounded inline-block border border-[var(--border-subtle)] shadow-inner">' + f.src_ip + ' ➔ ' + f.dst_ip + '</div>' +
                '<p class="text-[12px] text-[var(--text-muted)] mb-3 leading-relaxed">' + f.reason + '</p>' +
                '<div class="flex items-center justify-between">' +
                  '<div>' + tagsHtml + '</div>' +
                  '<div class="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-widest bg-[var(--bg-void)] px-2 py-0.5 rounded border border-[var(--border-subtle)]" style="color: ' + sevColor + ';">' + sevShape + ' ' + f.confidence + '</div>' +
                '</div></div>';
      }});
      detailsDiv.innerHTML = html;
    }}
  </script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as html_file:
        html_file.write(html_template)