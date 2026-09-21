"""
Unified Event Schema.

Standardizes raw Zeek log dictionaries into a single, predictable LmrEvent
dataclass. This abstracts away Zeek's specific column names from the detection logic.
"""

from dataclasses import dataclass
from typing import Any, Dict, Iterator, Optional


@dataclass
class LmrEvent:
    """A standardized network event ready for correlation and detection."""
    ts: float
    uid: str
    src_ip: str
    dst_ip: str
    service: str          # e.g., "smb_mapping", "dce_rpc"
    action: str           # e.g., "Share Mapped", "CreateServiceW"
    detail: str           # e.g., r"\\*\ADMIN$", "svcctl"
    account: Optional[str] = None


def normalize_zeek_logs(
    log_type: str, 
    raw_records: Iterator[Dict[str, Any]]
) -> Iterator[LmrEvent]:
    """
    Takes raw Zeek dictionaries and maps them to standard LmrEvents.
    Currently supports the logs needed for SMB/PsExec lateral movement.
    """
    for record in raw_records:
        # Every Zeek connection log has these base routing fields
        ts = float(record.get("ts", 0.0))
        uid = record.get("uid", "")
        src = record.get("id.orig_h", "")
        dst = record.get("id.resp_h", "")
        
        # We only want to yield valid, routable events
        if not (uid and src and dst):
            continue

        if log_type == "smb_mapping":
            yield LmrEvent(
                ts=ts,
                uid=uid,
                src_ip=src,
                dst_ip=dst,
                service="smb_mapping",
                action="Share Mapped",
                detail=record.get("path", ""),
                # smb_mapping does not natively log the user account, so we leave it None
            )

        elif log_type == "smb_files":
            yield LmrEvent(
                ts=ts,
                uid=uid,
                src_ip=src,
                dst_ip=dst,
                service="smb_files",
                action=record.get("action", "FILE_ACTION_UNKNOWN"),
                detail=record.get("name", ""),
            )

        elif log_type == "dce_rpc":
            # DCE/RPC (Distributed Computing Environment / Remote Procedure Calls)
            # Used by Windows to execute remote commands (like starting a service)
            yield LmrEvent(
                ts=ts,
                uid=uid,
                src_ip=src,
                dst_ip=dst,
                service="dce_rpc",
                action=record.get("operation", ""),
                detail=record.get("endpoint", ""),
            )