"""
RDP Lateral Movement Detection (MITRE ATT&CK T1021.001).
Analyzes normalized Zeek logs (rdp.log, ssl.log, conn.log) to identify 
internal Remote Desktop pivoting:
- Native RDP negotiation and cookie telemetry
- Port 3389 TLS/SSL handshakes (NLA/CredSSP)
- Defensive suppression of loopback and self-traffic
- Coercion across dirty Zeek TSVs
"""

import ipaddress
from typing import Iterable, Any
from lmr.schema import LmrEvent, DetectionFinding


def _is_loopback_or_self(src: str, dst: str) -> bool:
    """Filters local host traffic and interface-scoped self-traffic from lateral movement pivoting."""
    if not src or not dst or src == dst:
        return True
        
    # Strip interface identifiers (e.g., %eth0) from both sides
    clean_src = src.split("%")[0]
    clean_dst = dst.split("%")[0]
    
    # If the IPs match after stripping the scope, it's self-traffic
    if clean_src == clean_dst:
        return True
        
    # Check for loopback, unspecified, or multicast boundaries
    for ip_str in (clean_src, clean_dst):
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_multicast:
                return True
        except (ValueError, AttributeError):
            continue
            
    return False


def detect_rdp(events: Iterable[Any]) -> Iterable[DetectionFinding]:
    """
    Detects RDP-based lateral movement across network events.
    Examines rdp.log attributes (cookie, selected_security, client_build)
    and port 3389 transport streams.
    """
    for event in events:
        try:
            raw_src = getattr(event, "src_ip", "")
            raw_dst = getattr(event, "dst_ip", "")
            src_ip = str(raw_src or "0.0.0.0")
            dst_ip = str(raw_dst or "0.0.0.0")

            if _is_loopback_or_self(src_ip, dst_ip):
                continue

            raw_port = getattr(event, "dst_port", 0)
            try:
                dst_port = int(raw_port)
            except (ValueError, TypeError):
                dst_port = 0

            # Safe string extractions
            service = str(getattr(event, "service", "") or "").lower()
            cookie = str(getattr(event, "cookie", "") or "")
            selected_security = str(getattr(event, "selected_security", "") or "").upper()
            client_name = str(getattr(event, "client_name", "") or "")

            # Core Indicators
            is_rdp_port = dst_port == 3389
            is_rdp_service = service == "rdp"
            has_rdp_cookie = "mstshash=" in cookie.lower()
            has_valid_sec = selected_security in ("HYBRID", "HYBRID_EX", "SSL", "RDP")

            # High confidence: Confirmed RDP protocol semantics (cookie, security negotiated, or rdp service)
            # Medium confidence: Raw transport hit on port 3389 without parsed upper-layer fields
            if has_rdp_cookie or (is_rdp_service and has_valid_sec):
                confidence = "High"
                reason_parts = [f"Port: {dst_port}"]
                if cookie:
                    reason_parts.append(f"Cookie: {cookie}")
                if selected_security:
                    reason_parts.append(f"Security: {selected_security}")
                if client_name:
                    reason_parts.append(f"Client: {client_name}")
                reason = f"RDP session negotiation ({', '.join(reason_parts)})"

            elif is_rdp_port or is_rdp_service:
                confidence = "Medium"
                reason = f"RDP transport traffic detected (Port: {dst_port}, Service: {service or 'Unknown'})"
            else:
                continue

            uid_val = str(getattr(event, "uid", "UNKNOWN") or "UNKNOWN")

            yield DetectionFinding(
                rule_id="LMR-RDP-001",
                title="RDP Lateral Movement",
                attack_ids=["T1021.001"],
                confidence=confidence,
                src_ip=src_ip,
                dst_ip=dst_ip,
                evidence_uids=[uid_val],
                reason=reason,
            )
        except Exception:
            continue