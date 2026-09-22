"""
Kerberos Lateral Movement & Identity Abuse Detection (MITRE ATT&CK T1558).
Analyzes Zeek kerberos.log to identify Kerberoasting (T1558.003).
- Immediately flags weak cipher downgrades (RC4, DES).
- Behaviorally flags AES Kerberoasting via service sweep velocity tracking.
"""

import ipaddress
import urllib.parse
import re
from collections import defaultdict
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

def _safe_string_lower(val: Any) -> str:
    """Safely extracts, decodes, and sanitizes strings, crushing Zalgo and homoglyphs."""
    if isinstance(val, bool):
        return ""
    try:
        if isinstance(val, (bytes, bytearray, memoryview)):
            val = bytes(val).decode("utf-8", errors="ignore")
            
        s = str(val)
        s = urllib.parse.unquote(s) 
        
        # Strip everything except letters, numbers, and hyphens
        s = re.sub(r'[^a-zA-Z0-9\-]', '', s.lower())
        return s
    except Exception:
        return ""

def detect_kerberos(events: Iterable[Any]) -> Iterable[DetectionFinding]:
    """Scans Kerberos events for RC4/DES downgrades and AES Kerberoasting sweeps."""
    
    # State tracking for AES velocity: {src_ip: set([service1, service2, ...])}
    aes_tracker = defaultdict(set)
    aes_alerted = set()

    for event in events:
        try:
            raw_src = getattr(event, "src_ip", "")
            raw_dst = getattr(event, "dst_ip", "")
            src_ip = str(raw_src or "0.0.0.0")
            dst_ip = str(raw_dst or "0.0.0.0")

            if _is_loopback_or_self(src_ip, dst_ip):
                continue

            request_type = _safe_string_lower(getattr(event, "request_type", ""))
            cipher = _safe_string_lower(getattr(event, "cipher", ""))
            
            if "tgs" not in request_type:
                continue

            # Safely stringify the service to survive unhashable dictionary injections
            try:
                service = str(getattr(event, "service", "unknown")).strip()
            except Exception:
                service = "unknown"
                
            uid_val = str(getattr(event, "uid", "UNKNOWN") or "UNKNOWN")

            # 1. Static Signature: Exact tuple matching prevents "123" from triggering "23"
            is_rc4 = "rc4" in cipher or cipher in ("23", "0x17")
            is_des = "des" in cipher or cipher in ("1", "3", "0x01", "0x03")

            if is_rc4 or is_des:
                cipher_name = "RC4" if is_rc4 else "DES"
                yield DetectionFinding(
                    rule_id="LMR-KERB-001",
                    title=f"Kerberoasting (Weak Cipher {cipher_name} Downgrade)",
                    attack_ids=["T1558.003"],
                    confidence="High",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    evidence_uids=[uid_val],
                    reason=f"{cipher_name} cipher requested for TGS service ticket ({service})",
                )
                continue
            
            # 2. Behavioral Velocity: Check for AES Sweeps
            is_aes = "aes" in cipher or cipher in ("17", "18", "0x11", "0x12")
            
            if is_aes and src_ip not in aes_alerted:
                if service and service.lower() != "unknown":
                    aes_tracker[src_ip].add(service)
                    
                    if len(aes_tracker[src_ip]) > 5:
                        aes_alerted.add(src_ip)
                        yield DetectionFinding(
                            rule_id="LMR-KERB-002",
                            title="Kerberoasting (AES Service Sweep)",
                            attack_ids=["T1558.003"],
                            confidence="Medium",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            evidence_uids=[uid_val],
                            reason=f"Anomalous AES TGS sweep detected (>5 unique services requested by {src_ip})",
                        )
        except Exception:
            continue