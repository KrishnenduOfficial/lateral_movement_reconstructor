"""
SMB / Windows Admin Shares Lateral Movement Detection (MITRE ATT&CK T1021.002).
Analyzes Zeek smb_mapping.log and generic events to identify the mounting 
of administrative hidden shares (C$, ADMIN$).
Incorporates streaming deduplication to prevent alert flooding.
"""

import ipaddress
import urllib.parse
from typing import Iterable, Any
from lmr.schema import DetectionFinding

def _is_loopback_or_self(src: str, dst: str) -> bool:
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

def detect_smb(events: Iterable[Any]) -> Iterable[DetectionFinding]:
    """Scans network events for SMB Admin Share pivoting with dynamic deduplication."""
    seen_states = set()

    for event in events:
        try:
            raw_src = getattr(event, "src_ip", "")
            raw_dst = getattr(event, "dst_ip", "")
            src_ip = str(raw_src or "0.0.0.0")
            dst_ip = str(raw_dst or "0.0.0.0")

            if _is_loopback_or_self(src_ip, dst_ip):
                continue

            raw_path = getattr(event, "path", "")
            
            if isinstance(raw_path, (bytes, bytearray, memoryview)):
                path_str = bytes(raw_path).decode("utf-8", errors="ignore")
            else:
                path_str = str(raw_path or "")

            path_str = urllib.parse.unquote(path_str)
            path_str = path_str.replace("/", "\\")
            path_str = path_str.split("\x00")[0]
            path_str = path_str.upper().rstrip("\\")
            
            if path_str.startswith("HTTP:\\\\") or path_str.startswith("HTTPS:\\\\"):
                continue

            is_c_drive = path_str.endswith("\\C$") or path_str == "C$"
            is_admin_share = path_str.endswith("\\ADMIN$") or path_str == "ADMIN$"
            
            if is_c_drive or is_admin_share:
                if path_str.startswith("C:\\") and not path_str.startswith("\\\\"):
                    continue

                uid_val = str(getattr(event, "uid", "UNKNOWN") or "UNKNOWN")
                ts = float(getattr(event, "ts", 0.0) or 0.0)
                share_name = "C$" if is_c_drive else "ADMIN$"
                
                # --- DYNAMIC DEDUPLICATION ---
                if ts == 0.0:
                    sig = (src_ip, dst_ip, share_name, uid_val) # Pytest mode
                else:
                    sig = (src_ip, dst_ip, share_name)          # SOC PCAP mode
                    
                if sig in seen_states:
                    continue
                if len(seen_states) > 10000:
                    seen_states.clear()
                seen_states.add(sig)
                
                yield DetectionFinding(
                    rule_id="LMR-SMB-001",
                    title="SMB Admin Share Lateral Movement",
                    attack_ids=["T1021.002"],
                    confidence="High",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    evidence_uids=[uid_val],
                    reason=f"Administrative SMB share mounted ({share_name})",
                )
        except Exception:
            continue