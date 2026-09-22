"""
Apex-Predator Linux Infrastructure Fuzzing Suite (MITRE ATT&CK T1021.002, T1609).
Engineered for military-grade resilience against:
- Port integer obfuscation (hex strings, scientific notation, float truncation).
- Out-of-bounds port attacks and negative integer injections.
- Absolute schema destruction (recursive objects, unexecuted lambdas).
- Topology spoofing and hyperscale stream processing.
"""

import types
import pytest
import math
from typing import Any
from lmr.detections.linux_infra import detect_linux_infra

class MockConnEvent:
    def __init__(self, dst_port: Any = 2375, src_ip: Any = "10.0.10.55", 
                 dst_ip: Any = "10.0.20.100", uid: Any = "C_LNX_OMNI"):
        self.uid = uid
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port

# ==============================================================================
# TIER 1: Port Semantics, Evasion, and Bounds Checking (18 Cases)
# ==============================================================================

PORT_PAYLOADS = [
    ("native_docker", 2375, 1, "High"),
    ("native_nfs", 2049, 1, "Medium"),
    ("native_redis", 6379, 1, "High"),
    ("string_docker", "2375", 1, "High"),
    ("float_docker", 2375.0, 1, "High"),
    ("string_float_nfs", "2049.9", 1, "Medium"),       # Truncates to 2049
    ("scientific_redis", "6.379e3", 1, "High"),        # 6.379 * 1000 = 6379
    ("padded_string", "   2375 \n\t", 1, "High"),
    ("hex_string", "0x0947", 0, "None"),               # 2375 in hex -> float cast fails -> 0
    ("benign_ssh", 22, 0, "None"),
    ("benign_http", 80, 0, "None"),
    ("out_of_bounds_high", 70000, 0, "None"),          # > 65535 should drop
    ("out_of_bounds_low", -2375, 0, "None"),           # Negative ports should drop
    ("zero_port", 0, 0, "None"),
    ("nan_string", "nan", 0, "None"),
    ("inf_string", "inf", 0, "None"),
    ("native_nan_float", float('nan'), 0, "None"),
    ("corrupted_string", "two_thousand", 0, "None"),
]

@pytest.mark.parametrize(
    "name, port_val, expected_count, expected_confidence", 
    PORT_PAYLOADS,
    ids=[item[0] for item in PORT_PAYLOADS]
)
def test_port_semantics_and_bounds(name: str, port_val: Any, expected_count: int, expected_confidence: str) -> None:
    event = MockConnEvent(dst_port=port_val)
    findings = list(detect_linux_infra([event]))
    assert len(findings) == expected_count
    if expected_count > 0:
        assert findings[0].confidence == expected_confidence

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
    event = MockConnEvent(src_ip=src, dst_ip=dst, dst_port=6379)
    findings = list(detect_linux_infra([event]))
    assert len(findings) == expected_count

# ==============================================================================
# TIER 3: Absolute Schema Paradoxes (11 Cases)
# ==============================================================================

class ExplodingObject:
    def __str__(self):
        raise ValueError("Boom")

class RecursiveDestructor:
    def __init__(self):
        self.loop = self
    def __str__(self):
        return "2049"

SCHEMA_PAYLOADS = [
    ("bytearray_payload", bytearray(b"6379"), 1),
    ("memoryview_payload", memoryview(b"2375"), 1),
    ("recursive_object", RecursiveDestructor(), 1),
    ("exploding_object", ExplodingObject(), 0),
    ("unexecuted_lambda", lambda x: x, 0),                        
    ("builtin_class", int, 0),                                
    ("exception_object", Exception("Inner error"), 0),       
    ("deep_json_dict", {"nested": {"port": 2375}}, 0), 
    ("null_value", None, 0),
    ("huge_string", "A" * 50_000, 0),
    ("boolean_true", True, 0), # True casts to 1. Port 1 is not in TARGET_PORTS.
]

@pytest.mark.parametrize(
    "name, hostile_type, expected_count", 
    SCHEMA_PAYLOADS,
    ids=[item[0] for item in SCHEMA_PAYLOADS]
)
def test_omni_type_coercion_survival(name: str, hostile_type: Any, expected_count: int) -> None:
    event = MockConnEvent(dst_port=hostile_type)
    findings = list(detect_linux_infra([event]))
    assert len(findings) == expected_count

# ==============================================================================
# TIER 4: Hyper-Scale Generator Stability (1 Case)
# ==============================================================================

def test_hyperscale_100k_event_stream() -> None:
    def generate_hyperscale():
        for i in range(100_000):
            if i % 10_000 == 0:
                yield MockConnEvent(dst_port=2375, uid=f"APT-{i}")
            else:
                yield MockConnEvent(dst_port=443, uid=f"NOISE-{i}")

    stream = detect_linux_infra(generate_hyperscale())
    assert isinstance(stream, types.GeneratorType)
    
    findings = list(stream)
    assert len(findings) == 10
    assert findings[0].evidence_uids == ["APT-0"]
    assert findings[-1].evidence_uids == ["APT-90000"]