"""
Beyond-Insane SMB Admin Share Fuzzing Suite (MITRE ATT&CK T1021.002).
Engineered for military-grade resilience against:
- Share path obfuscation (mixed slashes, casing, null bytes, URL encoding).
- False positive suppression (IPC$ shares, legitimate file names, local paths).
- Absolute schema destruction (bytearrays, memoryviews, custom dunder objects).
- Hyper-scale stream processing.
"""

import types
import pytest
from typing import Any, Generator
from lmr.detections.smb import detect_smb

class MockSmbEvent:
    def __init__(self, path: Any = "\\\\10.0.20.100\\C$", src_ip: Any = "10.0.10.55", 
                 dst_ip: Any = "10.0.20.100", uid: Any = "C_SMB_OMNI"):
        self.uid = uid
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.path = path

# ==============================================================================
# TIER 1: Share Path Semantics & Advanced Evasion (20 Cases)
# ==============================================================================

PATH_PAYLOADS = [
    ("standard_c_share", "\\\\192.168.1.10\\C$", 1),
    ("standard_admin_share", "\\\\10.0.0.5\\ADMIN$", 1),
    ("lowercase_c_share", "\\\\10.0.0.5\\c$", 1),
    ("lowercase_admin_share", "\\\\10.0.0.5\\admin$", 1),
    ("forward_slashes", "//10.0.0.5/C$", 1),  
    ("mixed_slashes", "\\/10.0.0.5/\\C$", 1), 
    ("bare_c_share", "C$", 1),
    ("bare_admin_share", "ADMIN$", 1),
    ("benign_ipc_share", "\\\\10.0.0.5\\IPC$", 0),
    ("benign_sysvol", "\\\\10.0.0.5\\SYSVOL", 0),
    ("benign_print", "\\\\10.0.0.5\\PRINT$", 0),
    ("false_flag_folder", "\\\\10.0.0.5\\Shared\\C$", 1),
    ("embedded_null", "\\\\10.0.0.5\\C$\x00\\folder", 1), 
    ("zero_width_space", "\\\\10.0.0.5\\C\u200B$", 0), 
    ("device_path_unc", "\\\\?\\UNC\\10.0.0.5\\C$", 1),
    ("local_device_path", "\\\\.\\C$", 1),
    ("ipv6_literal", "\\\\2001-4860-4860--8888.ipv6-literal.net\\C$", 1),
    ("url_encoded", "%5C%5C10.0.0.5%5CC%24", 1),
    ("local_absolute_path", "C:\\Windows\\System32\\cmd.exe", 0),
    ("benign_url", "https://10.0.0.5/C$", 0), 
]

@pytest.mark.parametrize(
    "name, path_payload, expected_count", 
    PATH_PAYLOADS,
    ids=[item[0] for item in PATH_PAYLOADS]
)
def test_smb_path_matching(name: str, path_payload: str, expected_count: int) -> None:
    event = MockSmbEvent(path=path_payload)
    findings = list(detect_smb([event]))
    assert len(findings) == expected_count

# ==============================================================================
# TIER 2: Network Topology Suppression (12 Cases)
# ==============================================================================

TOPOLOGY_PAYLOADS = [
    ("octal_loopback", "0177.0000.0000.0001", "127.0.0.1", 0),
    ("hex_loopback", "0x7f000001", "127.0.0.1", 0),
    ("llmnr_multicast", "224.0.0.252", "224.0.0.252", 0),
    ("aws_metadata_apipa", "169.254.169.254", "169.254.169.254", 0),
    ("interface_scoped", "10.0.5.5", "10.0.5.5%eth0", 0),
    ("ipv6_loopback", "::1", "::1", 0),
    ("ipv4_mapped_ipv6", "::ffff:127.0.0.1", "::ffff:127.0.0.1", 0),
    ("link_local_ipv6", "fe80::1", "fe80::1", 0),
    ("same_private_ip", "192.168.1.1", "192.168.1.1", 0),
    ("valid_lateral_ipv4", "10.0.10.55", "10.0.20.100", 1),       
    ("valid_cgnat_lateral", "100.64.0.5", "100.64.0.6", 1),       
    ("valid_lateral_ipv6", "2001:db8::1", "2001:db8::2", 1),      
]

@pytest.mark.parametrize(
    "name, src, dst, expected_count", 
    TOPOLOGY_PAYLOADS,
    ids=[item[0] for item in TOPOLOGY_PAYLOADS]
)
def test_topology_suppression(name: str, src: str, dst: str, expected_count: int) -> None:
    event = MockSmbEvent(src_ip=src, dst_ip=dst, path="C$")
    findings = list(detect_smb([event]))
    assert len(findings) == expected_count

# ==============================================================================
# TIER 3: Absolute Schema Destruction (11 Cases)
# ==============================================================================

class HostileObject:
    def __str__(self) -> str:
        return "\\\\10.0.0.5\\ADMIN$"
    def __repr__(self) -> str:
        return "Not_A_Path"

class RecursiveDestructor:
    def __init__(self):
        self.loop = self
    def __str__(self):
        return "\\\\10.0.0.5\\C$"

SCHEMA_PAYLOADS = [
    ("bytearray_payload", bytearray(b"\\\\10.0.0.5\\C$"), 1),
    ("memoryview_payload", memoryview(b"\\\\10.0.0.5\\ADMIN$"), 1),
    ("custom_object_dunder", HostileObject(), 1),
    ("recursive_object", RecursiveDestructor(), 1),              
    ("unexecuted_lambda", lambda x: x, 0),                        
    ("builtin_class", int, 0),                                
    ("exception_object", Exception("Inner error"), 0),       
    ("deep_json_dict", {"nested": {"path": "\\\\10.0.0.5\\C$"}}, 0), 
    ("float_nan", float('nan'), 0),
    ("null_value", None, 0),
    ("huge_string", "A" * 50_000, 0),
]

@pytest.mark.parametrize(
    "name, hostile_type, expected_count", 
    SCHEMA_PAYLOADS,
    ids=[item[0] for item in SCHEMA_PAYLOADS]
)
def test_omni_type_coercion_survival(name: str, hostile_type: Any, expected_count: int) -> None:
    event = MockSmbEvent(path=hostile_type)
    findings = list(detect_smb([event]))
    assert len(findings) == expected_count

# ==============================================================================
# TIER 4: Hyper-Scale Generator Stability (1 Case)
# ==============================================================================

def test_hyperscale_100k_event_stream() -> None:
    def generate_hyperscale():
        for i in range(100_000):
            if i % 10_000 == 0:
                yield MockSmbEvent(path="ADMIN$", uid=f"APT-{i}")
            else:
                yield MockSmbEvent(path="IPC$", uid=f"NOISE-{i}")

    stream = detect_smb(generate_hyperscale())
    assert isinstance(stream, types.GeneratorType)
    
    findings = list(stream)
    assert len(findings) == 10
    assert findings[0].evidence_uids == ["APT-0"]
    assert findings[-1].evidence_uids == ["APT-90000"]