"""
Unified Event Schema.

Standardizes raw Zeek log dictionaries into a single, predictable LmrEvent
object. Dynamically binds all Zeek columns to support advanced detection rules.
"""

from dataclasses import dataclass
from typing import Any, Dict, Iterator, Optional

class LmrEvent:
    """A standardized network event ready for correlation and detection."""
    def __init__(self, **kwargs):
        self.ts = kwargs.get("ts", 0.0)
        self.uid = kwargs.get("uid", "")
        self.src_ip = kwargs.get("src_ip", "")
        self.dst_ip = kwargs.get("dst_ip", "")
        self.service = kwargs.get("service", "")
        self.action = kwargs.get("action", "")
        self.detail = kwargs.get("detail", "")
        self.account = kwargs.get("account")
        self.dst_port = kwargs.get("dst_port", 0)
        
        # Dynamically attach all other raw Zeek fields (e.g., cookie, uri, success)
        for k, v in kwargs.items():
            if not hasattr(self, k):
                # Replace dots in Zeek fields (id.resp_p) with underscores for Python safety
                safe_key = k.replace(".", "_")
                setattr(self, safe_key, v)

def normalize_zeek_logs(
    log_type: str, 
    raw_records: Iterator[Dict[str, Any]]
) -> Iterator[LmrEvent]:
    """
    Takes raw Zeek dictionaries and maps them to standard LmrEvents.
    Dynamically passes all fields to support modular detection rules.
    """
    for record in raw_records:
        # 1. Safely extract mandatory routing fields
        try:
            ts = float(record.get("ts") or 0.0)
        except ValueError:
            ts = 0.0
            
        uid = record.get("uid") or ""
        src = record.get("id.orig_h") or ""
        dst = record.get("id.resp_h") or ""
        
        # We only yield valid, routable events
        if not (uid and src and dst):
            continue
            
        # 2. Safely extract destination port for detection modules
        raw_port = record.get("id.resp_p")
        try:
            dst_port = int(raw_port) if raw_port is not None else 0
        except ValueError:
            dst_port = 0

        # 3. Build the dynamic event data payload
        event_data = record.copy()
        event_data["ts"] = ts
        event_data["uid"] = uid
        event_data["src_ip"] = src
        event_data["dst_ip"] = dst
        event_data["dst_port"] = dst_port
        event_data["service"] = log_type
        
        # Default action/detail for unmapped protocols
        event_data["action"] = ""
        event_data["detail"] = ""

        # 4. Maintain explicit backward compatibility for psexec.py mapping
        if log_type == "smb_mapping":
            event_data["action"] = "Share Mapped"
            event_data["detail"] = record.get("path", "")
        elif log_type == "smb_files":
            event_data["action"] = record.get("action", "FILE_ACTION_UNKNOWN")
            event_data["detail"] = record.get("name", "")
        elif log_type == "dce_rpc":
            event_data["action"] = record.get("operation", "")
            event_data["detail"] = record.get("endpoint", "")

        yield LmrEvent(**event_data)


@dataclass
class DetectionFinding:
    """Represents a finalized, correlated lateral movement finding."""
    rule_id: str
    title: str
    attack_ids: list[str]
    confidence: str
    src_ip: str
    dst_ip: str
    evidence_uids: list[str]
    reason: str