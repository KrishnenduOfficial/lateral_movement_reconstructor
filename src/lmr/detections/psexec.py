"""
Detection rule for SMB/PsExec Lateral Movement.
Correlates SMB share mappings with DCE/RPC service creation.
"""

from collections import defaultdict
from typing import Iterator, List, Tuple

from lmr.schema import DetectionFinding, LmrEvent


def detect_psexec(events: Iterator[LmrEvent]) -> Iterator[DetectionFinding]:
    """
    Scans a stream of normalized LmrEvents for PsExec behavior.
    
    Heuristic:
    A single source IP maps the ADMIN$ or C$ share on a destination IP, 
    and subsequently issues DCE/RPC svcctl CreateServiceW/StartServiceW commands.
    """
    # Group events by communication pair: (src_ip, dst_ip)
    host_pairs: dict[Tuple[str, str], List[LmrEvent]] = defaultdict(list)
    
    for event in events:
        host_pairs[(event.src_ip, event.dst_ip)].append(event)
        
    for (src, dst), pair_events in host_pairs.items():
        admin_share_uids = []
        svcctl_uids = []
        
        # Sort chronologically to ensure the sequence makes sense
        pair_events.sort(key=lambda e: e.ts)
        
        for ev in pair_events:
            # Check for hidden admin share mapping
            if ev.service == "smb_mapping" and ev.action == "Share Mapped":
                if ev.detail and ("ADMIN$" in ev.detail.upper() or "C$" in ev.detail.upper()):
                    admin_share_uids.append(ev.uid)
            
            # Check for remote service manipulation
            elif ev.service == "dce_rpc" and ev.detail == "svcctl":
                if ev.action in ("CreateServiceW", "StartServiceW"):
                    svcctl_uids.append(ev.uid)
                    
        # If both behaviors exist between this host pair, trigger a finding
        if admin_share_uids and svcctl_uids:
            # Combine and deduplicate Zeek connection UIDs for evidence tracking
            uids = sorted(list(set(admin_share_uids + svcctl_uids)))
            
            yield DetectionFinding(
                rule_id="F-001",
                title="PsExec-style remote execution",
                attack_ids=["T1021.002", "T1569.002"],
                confidence="High",
                src_ip=src,
                dst_ip=dst,
                evidence_uids=uids,
                reason="ADMIN$/C$ share mapped and remote service created/started via DCE/RPC."
            )