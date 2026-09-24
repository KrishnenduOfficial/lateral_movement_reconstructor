"""
WinRM Lateral Movement Detection (MITRE ATT&CK T1021.006).
Hardened for enterprise DFIR and adversarial evasion:
- Multi-pass URL decoding and path canonicalization (evades WSMAN URL obfuscation)
- Suppression of loopback and self-traffic
- Resilient stream processing
"""

import ipaddress
import posixpath
import urllib.parse
from typing import Iterable, Any
from lmr.schema import DetectionFinding

def _is_loopback_or_self(src: str, dst: str) -> bool:
    if not src or not dst:
        return False
    if src == dst:
        return True
    for ip_str in (src, dst):
        try:
            clean_ip = ip_str.split("%")[0]
            ip_obj = ipaddress.ip_address(clean_ip)
            if ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_multicast:
                return True
        except (ValueError, AttributeError):
            continue
    return False

def _canonicalize_path(raw_uri: Any) -> str:
    if not isinstance(raw_uri, str):
        return ""
    cleaned = raw_uri.split("\x00")[0].replace("\r", "").replace("\n", "")
    unquoted = cleaned
    for _ in range(3):
        next_unquote = urllib.parse.unquote(unquoted)
        if next_unquote == unquoted:
            break
        unquoted = next_unquote
    path_part = unquoted.split("?")[0].split(";")[0]
    return posixpath.normpath(path_part).lower()

def detect_winrm(events: Iterable[Any]) -> Iterable[DetectionFinding]:
    """Scans network events for WinRM lateral movement with dynamic deduplication."""
    seen_states: set = set()

    for event in events:
        try:
            src_ip = str(getattr(event, "src_ip", "") or "0.0.0.0")
            dst_ip = str(getattr(event, "dst_ip", "") or "0.0.0.0")

            if _is_loopback_or_self(src_ip, dst_ip):
                continue

            try:
                dst_port = int(getattr(event, "dst_port", 0))
            except (ValueError, TypeError):
                dst_port = 0

            raw_uri = getattr(event, "uri", "")
            canonical_path = _canonicalize_path(raw_uri)

            is_wsman_endpoint = (
                canonical_path == "/wsman"
                or canonical_path.startswith("/wsman/")
                or canonical_path.endswith("/wsman")
                or "/wsman/" in canonical_path
            )
            is_winrm_port = dst_port in (5985, 5986)

            if is_winrm_port or is_wsman_endpoint:
                confidence = "High" if is_wsman_endpoint else "Medium"
                uid_val = str(getattr(event, "uid", "UNKNOWN") or "UNKNOWN")
                ts = float(getattr(event, "ts", 0.0) or 0.0)

                # --- DYNAMIC DEDUPLICATION ---
                if ts == 0.0:
                    sig = (src_ip, dst_ip, dst_port, canonical_path, uid_val)
                else:
                    sig = (src_ip, dst_ip, confidence)

                if sig in seen_states:
                    continue
                if len(seen_states) > 10000:
                    seen_states.clear()
                seen_states.add(sig)

                reason = f"WinRM traffic detected (Port: {dst_port}, Path: {canonical_path or 'Encrypted/Unknown'})"

                yield DetectionFinding(
                    rule_id="LMR-WINRM-001",
                    title="WinRM Lateral Movement",
                    attack_ids=["T1021.006"],
                    confidence=confidence,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    evidence_uids=[uid_val],
                    reason=reason,
                )
        except Exception:
            continue