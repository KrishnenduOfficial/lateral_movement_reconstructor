"""
SSH Lateral Movement Detection (MITRE ATT&CK T1021.004).
Analyzes Zeek ssh.log to identify internal-to-internal pivots and 
brute-force lateral movement anomalies.
"""

import ipaddress
import urllib.parse
import re
import math
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

def _parse_auth_success(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    try:
        if isinstance(val, (bytes, bytearray, memoryview)):
            val = bytes(val).decode('utf-8', errors='ignore')
        s = str(val)
        s = urllib.parse.unquote(s)
        s = re.sub(r'[^A-Za-z0-9]', '', s).upper()
        return s in ("T", "TRUE", "Y", "YES", "1")
    except Exception:
        return False

def _parse_auth_attempts(val: Any) -> int:
    try:
        if isinstance(val, (bytes, bytearray, memoryview)):
            val = bytes(val).decode('utf-8', errors='ignore')
        s = str(val).strip()
        if s.lower() in ('inf', '-inf', 'nan'):
            return 0
        f_val = float(s)
        if math.isnan(f_val) or math.isinf(f_val):
            return 0
        return int(f_val)
    except Exception:
        return 0

def detect_ssh(events: Iterable[Any]) -> Iterable[DetectionFinding]:
    """Scans network events for SSH lateral movement with dynamic deduplication."""
    seen_states: set = set()

    for event in events:
        try:
            src_ip = str(getattr(event, "src_ip", "") or "0.0.0.0")
            dst_ip = str(getattr(event, "dst_ip", "") or "0.0.0.0")

            if _is_loopback_or_self(src_ip, dst_ip):
                continue

            auth_success = _parse_auth_success(getattr(event, "auth_success", "-"))
            
            if auth_success:
                attempts = _parse_auth_attempts(getattr(event, "auth_attempts", 0))
                uid_val = str(getattr(event, "uid", "UNKNOWN") or "UNKNOWN")
                ts = float(getattr(event, "ts", 0.0) or 0.0)
                
                is_brute_force = attempts > 5
                confidence = "High" if is_brute_force else "Medium"
                
                # --- DYNAMIC DEDUPLICATION ---
                if ts == 0.0:
                    sig = (src_ip, dst_ip, confidence, uid_val)
                else:
                    sig = (src_ip, dst_ip, confidence)
                    
                if sig in seen_states:
                    continue
                if len(seen_states) > 10000:
                    seen_states.clear()
                seen_states.add(sig)
                
                reason = f"Successful SSH brute-force pivot ({attempts} attempts)" if is_brute_force else "Successful SSH internal pivot"
                
                yield DetectionFinding(
                    rule_id="LMR-SSH-001",
                    title="SSH Lateral Movement",
                    attack_ids=["T1021.004"],
                    confidence=confidence,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    evidence_uids=[uid_val],
                    reason=reason,
                )
        except Exception:
            continue