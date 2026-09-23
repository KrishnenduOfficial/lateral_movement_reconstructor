"""
RDP Lateral Movement Detection (MITRE ATT&CK T1021.001).
Analyzes normalized Zeek logs (rdp.log, ssl.log, conn.log) to identify 
internal Remote Desktop pivoting:
- Native RDP negotiation and cookie telemetry
- Port 3389 TLS/SSL handshakes (NLA/CredSSP)
- Defines Private Network Boundaries (RFC 1918)
- Real-time deduplication to prevent alert flooding
- Defeats Cookie Evasion (Zero-width, RTLO, Buffer Bombs)
"""

import ipaddress
import re
import urllib.parse
from typing import Iterable, Any
from lmr.schema import DetectionFinding

def _is_private_ip(ip_str: str) -> bool:
    if not ip_str or ip_str == "0.0.0.0":
        return False
    try:
        clean_ip = ip_str.split("%")[0]
        return ipaddress.ip_address(clean_ip).is_private
    except ValueError:
        return False

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

def detect_rdp(events: Iterable[Any]) -> Iterable[DetectionFinding]:
    """
    Detects RDP-based lateral movement across network events.
    Examines rdp.log attributes (cookie, selected_security, client_build)
    and port 3389 transport streams. Incorporates stream-safe deduplication.
    """
    seen_states = set()

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

            service = str(getattr(event, "service", "") or "").lower()
            
            # Evasion-safe string extraction
            cookie_raw = str(getattr(event, "cookie", "") or "")
            cookie = urllib.parse.unquote(cookie_raw)
            
            # C-string termination: truncate exactly at the null byte
            cookie = cookie.split('\x00')[0]
            
            # Remove zero-width spaces and RTLO used in evasion
            cookie = re.sub(r'[\u200b\u202e]', '', cookie)
            
            selected_security = str(getattr(event, "selected_security", "") or "").upper()
            client_name = str(getattr(event, "client_name", "") or "")

            # Core Indicators
            is_rdp_port = dst_port == 3389
            is_rdp_service = service == "rdp"
            has_rdp_cookie = "mstshash=" in cookie.lower()
            has_valid_sec = selected_security in ("HYBRID", "HYBRID_EX", "SSL", "RDP")

            # High confidence: Confirmed RDP protocol semantics
            if has_rdp_cookie or (is_rdp_service and has_valid_sec):
                confidence = "High"
                reason_parts = [f"Port: {dst_port}"]
                if cookie:
                    # Truncate to 50 chars to defeat massive buffer bomb bloat
                    reason_parts.append(f"Cookie: {cookie[:50]}")
                if selected_security:
                    reason_parts.append(f"Security: {selected_security}")
                if client_name:
                    reason_parts.append(f"Client: {client_name}")
                reason = f"RDP session negotiation ({', '.join(reason_parts)})"

            # Medium confidence: Raw transport hit
            elif is_rdp_port or is_rdp_service:
                confidence = "Medium"
                reason = f"RDP transport traffic detected (Port: {dst_port}, Service: {service or 'Unknown'})"
            else:
                continue

            # --- STREAMING DEDUPLICATION ---
            # Group identical behaviors to stop alert flooding (e.g. 29,412 WCCDC alerts -> 1)
            sig = (src_ip, dst_ip, confidence, cookie[:50], selected_security)
            if sig in seen_states:
                continue
                
            # Memory safety: Prevent attacker-controlled field bloat from killing the SOC engine
            if len(seen_states) > 10000:
                seen_states.clear()
                
            seen_states.add(sig)
            # -------------------------------

            # Differentiate true lateral movement vs external ingress
            is_src_priv = _is_private_ip(src_ip)
            is_dst_priv = _is_private_ip(dst_ip)
            
            if not is_src_priv and is_dst_priv:
                title = "External RDP Ingress"
                rule_id = "LMR-RDP-INGRESS"
            else:
                title = "RDP Lateral Movement"
                rule_id = "LMR-RDP-001"

            uid_val = str(getattr(event, "uid", "UNKNOWN") or "UNKNOWN")

            yield DetectionFinding(
                rule_id=rule_id,
                title=title,
                attack_ids=["T1021.001", "T1133"] if not is_src_priv else ["T1021.001"],
                confidence=confidence,
                src_ip=src_ip,
                dst_ip=dst_ip,
                evidence_uids=[uid_val],
                reason=reason,
            )
        except Exception:
            continue