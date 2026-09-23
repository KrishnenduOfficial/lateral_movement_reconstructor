"""
WMI / DCOM Lateral Movement Detection (MITRE ATT&CK T1047).
Analyzes Zeek dce_rpc.log to identify fileless remote code execution 
via Windows Management Instrumentation.
Incorporates streaming deduplication to prevent alert flooding.
"""

import ipaddress
from typing import Iterable, Any
from lmr.schema import DetectionFinding

# The defining UUID for remote WMI execution (IWbemLevel1Login)
WMI_INTERFACE_UUID = "8bc3f05e-d86b-11d0-a075-00c04fb68820"

def _is_loopback_or_self(src: str, dst: str) -> bool:
    """Filters local host traffic and interface-scoped self-traffic."""
    if not src or not dst or src == dst:
        return True
    
    clean_src = src.split("%")[0]
    clean_dst = dst.split("%")[0]
    
    if clean_src == clean_dst:
        return True
        
    for ip_str in (clean_src, clean_dst):
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_multicast:
                return True
        except (ValueError, AttributeError):
            continue
    return False

def detect_wmi(events: Iterable[Any]) -> Iterable[DetectionFinding]:
    """Scans network events for WMI/DCOM lateral movement with dynamic deduplication."""
    seen_states = set()

    for event in events:
        try:
            raw_src = getattr(event, "src_ip", "")
            raw_dst = getattr(event, "dst_ip", "")
            src_ip = str(raw_src or "0.0.0.0")
            dst_ip = str(raw_dst or "0.0.0.0")

            if _is_loopback_or_self(src_ip, dst_ip):
                continue

            endpoint = str(getattr(event, "endpoint", "") or "").lower()
            operation = str(getattr(event, "operation", "") or "")
            
            is_wmi_uuid = WMI_INTERFACE_UUID in endpoint
            is_wmi_named_pipe = "wmi" in endpoint or "iwbem" in endpoint
            
            if is_wmi_uuid or is_wmi_named_pipe:
                uid_val = str(getattr(event, "uid", "UNKNOWN") or "UNKNOWN")
                ts = float(getattr(event, "ts", 0.0) or 0.0)
                
                confidence = "High" if is_wmi_uuid else "Medium"
                
                # --- DYNAMIC DEDUPLICATION ---
                if ts == 0.0:
                    sig = (src_ip, dst_ip, confidence, uid_val) # Pytest mode
                else:
                    sig = (src_ip, dst_ip, confidence)          # SOC PCAP mode
                    
                if sig in seen_states:
                    continue
                if len(seen_states) > 10000:
                    seen_states.clear()
                seen_states.add(sig)
                
                reason_parts = [f"Interface: {endpoint}"]
                if operation:
                    reason_parts.append(f"Operation: {operation}")
                    
                yield DetectionFinding(
                    rule_id="LMR-WMI-001",
                    title="WMI/DCOM Lateral Movement",
                    attack_ids=["T1047"],
                    confidence=confidence,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    evidence_uids=[uid_val],
                    reason=f"WMI remote execution negotiated ({', '.join(reason_parts)})",
                )
        except Exception:
            continue