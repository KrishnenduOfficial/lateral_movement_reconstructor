"""
WinRM Lateral Movement Detection (MITRE ATT&CK T1021.006).
Hardened for enterprise DFIR and adversarial evasion:
- Multi-pass URL decoding and path canonicalization (evades WSMAN URL obfuscation)
- Suppression of loopback and self-traffic (prevents local execution false positives)
- Resilient stream processing (survives poisoned non-event items in generators)
- Defensive type coercion across dirty Zeek TSVs
"""

import ipaddress
import posixpath
import urllib.parse
from typing import Iterable, Any
from lmr.schema import LmrEvent, DetectionFinding


def _is_loopback_or_self(src: str, dst: str) -> bool:
    """Determines if the connection is self-traffic or loopback (not lateral movement)."""
    if not src or not dst:
        return False
    if src == dst:
        return True
    for ip_str in (src, dst):
        try:
            # Strip IPv6 interface zone/scope identifier if present (e.g., fe80::1%eth0)
            clean_ip = ip_str.split("%")[0]
            ip_obj = ipaddress.ip_address(clean_ip)
            if ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_multicast:
                return True
        except (ValueError, AttributeError):
            continue
    return False


def _canonicalize_path(raw_uri: Any) -> str:
    """
    Recursively decodes percent-encoded URIs, truncates at null bytes,
    and canonicalizes relative path traversal sequences (/../, //, /./).
    """
    if not isinstance(raw_uri, str):
        return ""

    # Truncate at null byte (simulates C string termination / WAF evasion)
    # and strip newlines / carriage returns
    cleaned = raw_uri.split("\x00")[0].replace("\r", "").replace("\n", "")

    # Multi-pass URL decode (handles single and double percent-encoding)
    unquoted = cleaned
    for _ in range(3):
        next_unquote = urllib.parse.unquote(unquoted)
        if next_unquote == unquoted:
            break
        unquoted = next_unquote

    # Strip query strings and matrix parameters for path analysis
    path_part = unquoted.split("?")[0].split(";")[0]

    # Canonicalize path segments (e.g., /foo/../wsman -> /wsman)
    norm_path = posixpath.normpath(path_part)
    return norm_path.lower()


def detect_winrm(events: Iterable[Any]) -> Iterable[DetectionFinding]:
    """
    Scans network events for WinRM lateral movement (T1021.006).
    Yields DetectionFinding objects while isolating errors on malformed events.
    """
    for event in events:
        try:
            # 1. Defensively extract and coerce IPs
            raw_src = getattr(event, "src_ip", "")
            raw_dst = getattr(event, "dst_ip", "")
            src_ip = str(raw_src or "0.0.0.0")
            dst_ip = str(raw_dst or "0.0.0.0")

            # Suppress self-traffic and loopback (local execution != lateral movement)
            if _is_loopback_or_self(src_ip, dst_ip):
                continue

            # 2. Defensively extract port
            raw_port = getattr(event, "dst_port", 0)
            try:
                dst_port = int(raw_port)
            except (ValueError, TypeError):
                dst_port = 0

            # 3. Canonicalize URI path
            raw_uri = getattr(event, "uri", "")
            canonical_path = _canonicalize_path(raw_uri)

            # 4. Strict endpoint detection
            # Valid WSMAN endpoints must be /wsman, /wsman/..., or end with /wsman
            # Avoid false positives like /wsman_backup_file.txt or /wsman-guide.html
            is_wsman_endpoint = (
                canonical_path == "/wsman"
                or canonical_path.startswith("/wsman/")
                or canonical_path.endswith("/wsman")
                or "/wsman/" in canonical_path
            )
            is_winrm_port = dst_port in (5985, 5986)

            if is_winrm_port or is_wsman_endpoint:
                confidence = "High" if is_wsman_endpoint else "Medium"
                raw_uid = getattr(event, "uid", "UNKNOWN")
                uid_val = str(raw_uid or "UNKNOWN")
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
            # Stream Poisoning Protection: malformed items never crash the pipeline
            continue