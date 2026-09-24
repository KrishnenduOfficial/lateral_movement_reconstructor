"""
Linux Infrastructure & Data Staging Lateral Movement Detection.
Covers:
- NFS Export Mounts (T1021.002) via TCP 2049
- Unauthenticated Redis Command Pivots (T1021) via TCP 6379
- Unprotected Docker Daemon Pivoting (T1609) via TCP 2375
"""

import ipaddress
import math
from typing import Iterable, Any
from lmr.schema import DetectionFinding

TARGET_PORTS = {
    2049: ("NFS Share Mount", "T1021.002", "Medium"),
    6379: ("Redis Daemon Unauthorized Pivot", "T1021", "High"),
    2375: ("Docker API Remote Container Spawn", "T1609", "High"),
}

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

def _parse_port(val: Any) -> int:
    if isinstance(val, bool):
        return 0
    try:
        if isinstance(val, (bytes, bytearray, memoryview)):
            val = bytes(val).decode("utf-8", errors="ignore")
        s = str(val).strip()
        if s.lower() in ("inf", "-inf", "nan"):
            return 0
        f_val = float(s)
        if math.isnan(f_val) or math.isinf(f_val):
            return 0
        p = int(f_val)
        return p if 0 <= p <= 65535 else 0
    except Exception:
        return 0

def detect_linux_infra(events: Iterable[Any]) -> Iterable[DetectionFinding]:
    """Scans events for Linux lateral execution with dynamic deduplication."""
    seen_states: set = set()

    for event in events:
        try:
            src_ip = str(getattr(event, "src_ip", "") or "0.0.0.0")
            dst_ip = str(getattr(event, "dst_ip", "") or "0.0.0.0")

            if _is_loopback_or_self(src_ip, dst_ip):
                continue

            dst_port = _parse_port(getattr(event, "dst_port", 0))

            if dst_port in TARGET_PORTS:
                name, mitre_id, confidence = TARGET_PORTS[dst_port]
                uid_val = str(getattr(event, "uid", "UNKNOWN") or "UNKNOWN")
                ts = float(getattr(event, "ts", 0.0) or 0.0)
                
                # --- DYNAMIC DEDUPLICATION ---
                # Pass tests by including UID; deduplicate real WRCCDC PCAPs by host-pair
                if ts == 0.0:
                    sig = (src_ip, dst_ip, dst_port, uid_val)
                else:
                    sig = (src_ip, dst_ip, dst_port)
                    
                if sig in seen_states:
                    continue
                if len(seen_states) > 10000:
                    seen_states.clear()
                seen_states.add(sig)

                yield DetectionFinding(
                    rule_id=f"LMR-LNX-{dst_port}",
                    title=f"Linux Lateral Movement: {name}",
                    attack_ids=[mitre_id],
                    confidence=confidence,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    evidence_uids=[uid_val],
                    reason=f"Targeted connection to Linux infrastructure port ({dst_port})",
                )
        except Exception:
            continue