"""
Beyond-Insane WMI/DCOM Lateral Movement Fuzzing Suite (MITRE ATT&CK T1047).
Engineered for military-grade resilience against:
- DCE/RPC interface UUID obfuscation (URNs, braces, padding, homoglyphs).
- Extreme schema destruction (recursive objects, memory views, NaNs).
- Advanced topology spoofing (IPv4-mapped IPv6, CGNAT, LLMNR).
- Hyper-scale stream processing (100,000+ events) without memory leaks.
"""

import types
import pytest
from typing import Any, Generator
from lmr.detections.wmi import detect_wmi


class MockWmiEvent:
    def __init__(self, endpoint: Any = "8bc3f05e-d86b-11d0-a075-00c04fb68820", 
                 operation: Any = "RemoteCreateInstance", src_ip: Any = "10.0.10.55", 
                 dst_ip: Any = "10.0.20.100", uid: Any = "C_WMI_OMNI"):
        self.uid = uid
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.endpoint = endpoint
        self.operation = operation


# ==============================================================================
# TIER 1: Protocol Baselines & UUID Obfuscation (15 Cases)
# ==============================================================================

UUID_PAYLOADS = [
    ("exact_match", "8bc3f05e-d86b-11d0-a075-00c04fb68820", True, "High"),
    ("uppercase_uuid", "8BC3F05E-D86B-11D0-A075-00C04FB68820", True, "High"),
    ("braces_uuid", "{8bc3f05e-d86b-11d0-a075-00c04fb68820}", True, "High"),
    ("urn_uuid", "urn:uuid:8bc3f05e-d86b-11d0-a075-00c04fb68820", True, "High"),
    ("whitespace_padding", "   8bc3f05e-d86b-11d0-a075-00c04fb68820 \n\t ", True, "High"),
    ("null_byte_split", "8bc3f05e\x00-d86b-11d0-a075-00c04fb68820", False, "None"),  # Breaks strict UUID continuity
    ("zero_width_space", "8bc3f05e-\u200Bd86b-11d0-a075-00c04fb68820", False, "None"), # Breaks strict UUID continuity
    ("wmi_named_pipe_ncacn", "ncacn_np:[\\pipe\\wmi]", True, "Medium"),
    ("iwbem_named_pipe", "ncacn_np:[\\pipe\\iwbem]", True, "Medium"),
    ("benign_spooler_rpc", "spoolss", False, "None"),
    ("benign_epmapper", "epmapper", False, "None"),
    ("uuid_with_version_noise", "uuid:8bc3f05e-d86b-11d0-a075-00c04fb68820/version:1.0", True, "High"),
    ("cyrillic_homoglyph", "8bc3f05e-d86b-11d0-a075-00c04fb68820".replace("e", "е"), False, "None"), 
    ("url_encoded", "8bc3f05e-d86b-11d0-a075-00c04fb68820%20", True, "High"),
    ("double_injection", "8bc3f05e-d86b-11d0-a075-00c04fb688208bc3f05e-d86b-11d0-a075-00c04fb68820", True, "High"),
]

@pytest.mark.parametrize(
    "payload_name, endpoint_payload, expected_detection, expected_confidence", 
    UUID_PAYLOADS,
    ids=[item[0] for item in UUID_PAYLOADS]
)
def test_wmi_uuid_signature_matching(payload_name: str, endpoint_payload: str, expected_detection: bool, expected_confidence: str) -> None:
    event = MockWmiEvent(endpoint=endpoint_payload)
    findings = list(detect_wmi([event]))
    
    if expected_detection:
        assert len(findings) == 1
        assert findings[0].confidence == expected_confidence
    else:
        assert len(findings) == 0


# ==============================================================================
# TIER 2: Network Edge Cases & BGP/Anycast Spoofing (12 Cases)
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
    ("valid_lateral_ipv4", "10.0.10.55", "10.0.20.100", 1),       # Valid Cross-Host
    ("valid_cgnat_lateral", "100.64.0.5", "100.64.0.6", 1),       # Valid Carrier-Grade NAT
    ("valid_lateral_ipv6", "2001:db8::1", "2001:db8::2", 1),      # Valid Cross-Host IPv6
]

@pytest.mark.parametrize(
    "name, src, dst, expected_count", 
    TOPOLOGY_PAYLOADS,
    ids=[item[0] for item in TOPOLOGY_PAYLOADS]
)
def test_insane_topology_suppression(name: str, src: str, dst: str, expected_count: int) -> None:
    event = MockWmiEvent(src_ip=src, dst_ip=dst)
    findings = list(detect_wmi([event]))
    assert len(findings) == expected_count


# ==============================================================================
# TIER 3: Absolute Schema Destruction (10 Cases)
# ==============================================================================

class RecursiveDestructor:
    def __init__(self):
        self.loop = self
    def __str__(self):
        return "8bc3f05e-d86b-11d0-a075-00c04fb68820"

SCHEMA_PAYLOADS = [
    ("unexecuted_lambda", lambda x: x, 0),                        
    ("recursive_object", RecursiveDestructor(), 1),              
    ("builtin_class", int, 0),                                
    ("exception_object", Exception("Inner error"), 0),       
    ("deep_json_dict", {"nested": {"nested": "8bc3f05e-d86b-11d0-a075-00c04fb68820"}}, 1), 
    ("float_nan", float('nan'), 0),
    ("float_inf", float('inf'), 0),
    ("memory_view", memoryview(b"junk_data"), 0), 
    ("bytearray_payload", bytearray(b"8bc3f05e-d86b-11d0-a075-00c04fb68820"), 1), 
    ("null_value", None, 0),
]

@pytest.mark.parametrize(
    "name, hostile_type, expected_count", 
    SCHEMA_PAYLOADS,
    ids=[item[0] for item in SCHEMA_PAYLOADS]
)
def test_omni_type_coercion_survival(name: str, hostile_type: Any, expected_count: int) -> None:
    event = MockWmiEvent(endpoint=hostile_type)
    findings = list(detect_wmi([event]))
    assert len(findings) == expected_count


# ==============================================================================
# TIER 4: Operation String Buffer Bombs (4 Cases)
# ==============================================================================

OPERATION_PAYLOADS = [
    ("standard_op", "RemQueryInterface"), 
    ("massive_buffer_bomb", "A" * 50_000),           # 50KB string chunk
    ("null_op", None), 
    ("corrupted_dict", {"malformed": "dict"})
]

@pytest.mark.parametrize(
    "name, operation_payload", 
    OPERATION_PAYLOADS,
    ids=[item[0] for item in OPERATION_PAYLOADS]
)

def test_operation_field_corruption(name: str, operation_payload: Any) -> None:
    """The operation field shouldn't crash the engine even if completely corrupted."""
    event = MockWmiEvent(operation=operation_payload)
    findings = list(detect_wmi([event]))
    assert len(findings) == 1
    assert "WMI remote execution" in findings[0].reason


# ==============================================================================
# TIER 5: Hyper-Scale Generator Stability & Memory Safety (1 Case)
# ==============================================================================

def test_hyperscale_100k_event_stream() -> None:
    def generate_hyperscale():
        for i in range(100_000):
            if i % 10_000 == 0:
                yield MockWmiEvent(endpoint="8bc3f05e-d86b-11d0-a075-00c04fb68820", uid=f"APT-{i}")
            else:
                yield MockWmiEvent(endpoint="epmapper", operation="Bind", uid=f"NOISE-{i}")

    stream = detect_wmi(generate_hyperscale())
    assert isinstance(stream, types.GeneratorType)
    
    findings = list(stream)
    assert len(findings) == 10
    assert findings[0].evidence_uids == ["APT-0"]
    assert findings[-1].evidence_uids == ["APT-90000"]