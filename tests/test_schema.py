"""
Unit tests for the Unified Event Schema and Normalizer.
"""

from lmr.schema import normalize_zeek_logs


def test_normalize_smb_mapping():
    raw_records = [
        {
            "ts": "1600000000.0",
            "uid": "C123",
            "id.orig_h": "10.0.0.5",
            "id.resp_h": "10.0.0.20",
            "path": "\\\\10.0.0.20\\ADMIN$"
        }
    ]
    
    events = list(normalize_zeek_logs("smb_mapping", raw_records))
    
    assert len(events) == 1
    event = events[0]
    
    assert event.src_ip == "10.0.0.5"
    assert event.service == "smb_mapping"
    assert event.action == "Share Mapped"
    assert event.detail == "\\\\10.0.0.20\\ADMIN$"


def test_normalize_dce_rpc():
    raw_records = [
        {
            "ts": "1600000005.0",
            "uid": "C456",
            "id.orig_h": "10.0.0.5",
            "id.resp_h": "10.0.0.20",
            "endpoint": "svcctl",
            "operation": "CreateServiceW"
        }
    ]
    
    events = list(normalize_zeek_logs("dce_rpc", raw_records))
    assert len(events) == 1
    event = events[0]
    
    assert event.action == "CreateServiceW"
    assert event.detail == "svcctl"
    assert event.ts == 1600000005.0