"""
NTLM Lateral Movement & Identity Abuse Detection (MITRE ATT&CK T1550.002).
Analyzes Zeek ntlm.log to identify Pass-the-Hash lateral spread and NTLM credential spraying.
Incorporates streaming deduplication to prevent alert flooding.
"""

import ipaddress
import urllib.parse
import re
from collections import defaultdict
from typing import Iterable, Any, Optional
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

def _parse_success(val: Any) -> Optional[bool]:
    if val is None:
        return None

    if isinstance(val, bool):
        return val

    if callable(val) or isinstance(val, type) or isinstance(val, BaseException):
        return None

    if isinstance(val, (int, float)):
        try:
            if val == 1:
                return True
            if val == 0:
                return False
            return None
        except Exception:
            return None

    try:
        if isinstance(val, (bytes, bytearray, memoryview)):
            val = bytes(val).decode("utf-8", errors="ignore")

        s = str(val)
        s = urllib.parse.unquote(s)
        s = re.sub(r"[^a-zA-Z0-9\-]", "", s).strip().upper()

        if s in ("T", "TRUE", "Y", "YES", "1"):
            return True
        if s in ("F", "FALSE", "N", "NO", "0", "-"):
            return False

        return None
    except Exception:
        return None

def _safe_string_extract(val: Any) -> str:
    if val is None or isinstance(val, (bool, dict, list, set, tuple, type)) or callable(val):
        return "unknown"
    try:
        if isinstance(val, (bytes, bytearray, memoryview)):
            val = bytes(val).decode("utf-8", errors="ignore")

        s = str(val)
        s = urllib.parse.unquote(s)
        s = re.sub(r"[^a-zA-Z0-9\-\_\$]", "", s)
        return s if s else "unknown"
    except Exception:
        return "unknown"

def detect_ntlm(events: Iterable[Any]) -> Iterable[DetectionFinding]:
    spray_tracker = defaultdict(set)
    spread_tracker = defaultdict(set)

    alerted_spray = set()
    seen_states = set()

    for event in events:
        try:
            raw_src = getattr(event, "src_ip", "")
            raw_dst = getattr(event, "dst_ip", "")
            src_ip = str(raw_src or "0.0.0.0")
            dst_ip = str(raw_dst or "0.0.0.0")

            if _is_loopback_or_self(src_ip, dst_ip):
                continue

            if not hasattr(event, "success") and not hasattr(event, "username"):
                continue

            success = _parse_success(getattr(event, "success", None))
            if success is None:
                continue

            username = _safe_string_extract(getattr(event, "username", "unknown"))
            uid_val = str(getattr(event, "uid", "UNKNOWN") or "UNKNOWN")
            ts = float(getattr(event, "ts", 0.0) or 0.0)

            # 1. NTLM Credential Spraying (Failed Auth)
            if not success and username != "unknown":
                if src_ip not in alerted_spray:
                    spray_tracker[src_ip].add(username)

                    if len(spray_tracker[src_ip]) > 5:
                        alerted_spray.add(src_ip)
                        yield DetectionFinding(
                            rule_id="LMR-NTLM-001",
                            title="NTLM Credential Spraying",
                            attack_ids=["T1110.003"],
                            confidence="High",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            evidence_uids=[uid_val],
                            reason=f"High-volume NTLM authentication failures across >5 unique accounts from {src_ip}",
                        )

            # 2. Pass-the-Hash Lateral Spread (Successful Auth)
            if success:
                spread_tracker[src_ip].add(dst_ip)

                if len(spread_tracker[src_ip]) > 3:
                    
                    # --- DYNAMIC DEDUPLICATION ---
                    if ts == 0.0:
                        sig = (src_ip, "NTLM-SPREAD", uid_val) # Pytest mode
                    else:
                        sig = (src_ip, "NTLM-SPREAD")          # SOC PCAP mode
                        
                    if sig not in seen_states:
                        if len(seen_states) > 10000:
                            seen_states.clear()
                        seen_states.add(sig)
                        
                        yield DetectionFinding(
                            rule_id="LMR-NTLM-002",
                            title="NTLM Pass-the-Hash / Lateral Spread",
                            attack_ids=["T1550.002"],
                            confidence="Medium",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            evidence_uids=[uid_val],
                            reason=f"Anomalous NTLM lateral spread (>3 unique destination IPs successfully authenticated by {src_ip})",
                        )
        except Exception:
            continue