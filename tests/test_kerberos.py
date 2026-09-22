"""
Beyond-Insane Kerberos Identity Abuse Fuzzing Suite (MITRE ATT&CK T1558).
Engineered for military-grade resilience against:
- Exact-match integer evasion and substring false positive trapping.
- Cipher suite obfuscation (DES, RC4, hex codes, multi-layer URL encoding).
- Behavioral velocity evasion (interleaved AES noise, duplicate SPNs, state pollution).
- Absolute schema destruction (unhashable types in state trackers, exploding dunders).
"""

import types
import pytest
from typing import Any
from lmr.detections.kerberos import detect_kerberos

class MockKerbEvent:
    def __init__(self, request_type: Any = "TGS", cipher: Any = "rc4-hmac", 
                 service: Any = "MSSQLSvc/db01:1433", src_ip: Any = "10.0.10.55", 
                 dst_ip: Any = "10.0.20.100", uid: Any = "C_KERB_OMNI"):
        self.uid = uid
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.request_type = request_type
        self.cipher = cipher
        self.service = service

# ==============================================================================
# TIER 1: Exact-Match Evasion & Obfuscation (24 Cases)
# ==============================================================================

KERB_PAYLOADS = [
    # True Positives: RC4
    ("standard_rc4_string", "TGS", "rc4-hmac", 1),
    ("rc4_hmac_nt", "TGS", "rc4-hmac-nt", 1),
    ("hex_cipher_code_23", "TGS", "0x17", 1),
    ("int_cipher_code_23", "TGS", 23, 1),
    ("string_int_23", "TGS", "23", 1),
    
    # True Positives: DES
    ("standard_des_md5", "TGS", "des-cbc-md5", 1),
    ("standard_des_crc", "TGS", "des-cbc-crc", 1),
    ("des_hex_code_03", "TGS", "0x03", 1),
    ("des_hex_code_01", "TGS", "0x01", 1),
    ("des_int_code_3", "TGS", 3, 1),
    ("des_string_int_3", "TGS", "3", 1),
    
    # Substring Traps (Should NOT trigger exact match filters)
    ("false_flag_123", "TGS", 123, 0),             # Contains '23' and '3', but is exactly 123
    ("false_flag_33", "TGS", 33, 0),               # Contains '3', but is exactly 33
    ("false_flag_string_123", "TGS", "123", 0),    
    ("false_flag_string_0x170", "TGS", "0x170", 0), 

    # Advanced Obfuscation
    ("url_encoded_cipher", "TGS", "rc4%2Dhmac", 1),
    ("double_url_encoded", "TGS", "%72%63%34", 1),
    ("zero_width_space", "TGS", "d\u200Be\u200Bs", 1),
    ("zalgo_text", "T\u0337G\u0337S", "r\u0337c\u03374\u0337", 1),
    ("padded_cipher", "TGS", "   rc4-hmac \n", 1),
    
    # False Positives
    ("tgt_rc4_request", "TGT", "rc4-hmac", 0),
    ("as_req_rc4", "AS-REQ", "rc4-hmac", 0),
    ("aes256_tgs_single", "TGS", "aes256-cts-hmac-sha1-96", 0),  
    ("benign_service", "UNKNOWN", "rc4", 0),
]

@pytest.mark.parametrize(
    "name, req_type, cipher_val, expected_count", 
    KERB_PAYLOADS,
    ids=[item[0] for item in KERB_PAYLOADS]
)
def test_kerberos_semantics(name: str, req_type: Any, cipher_val: Any, expected_count: int) -> None:
    event = MockKerbEvent(request_type=req_type, cipher=cipher_val)
    findings = list(detect_kerberos([event]))
    assert len(findings) == expected_count


# ==============================================================================
# TIER 2: Stateful Behavioral Velocity Tracking (4 Cases)
# ==============================================================================

def test_aes_kerberoasting_velocity_standard():
    """Validates rapid AES requests across unique SPNs trigger a behavioral alert."""
    events = [
        MockKerbEvent(cipher="aes256", service=f"Service/{i}") for i in range(5)
    ]
    assert len(list(detect_kerberos(events))) == 0  # 5 services is threshold
    
    events.append(MockKerbEvent(cipher="aes256", service="Service/6"))
    findings = list(detect_kerberos(events))
    assert len(findings) == 1
    assert findings[0].confidence == "Medium"

def test_aes_kerberoasting_interleaved_noise():
    """Validates state tracker survives interleaved legitimate traffic and duplicate SPNs."""
    events = [
        MockKerbEvent(cipher="aes256", service="HTTP/web01", src_ip="10.0.10.55"),
        MockKerbEvent(cipher="aes256", service="HTTP/web01", src_ip="10.0.10.55"), # Duplicate
        MockKerbEvent(cipher="rc4-hmac", service="Legacy/app", src_ip="10.0.10.99"), # Different IP, RC4
        MockKerbEvent(cipher="aes256", service="MSSQL/db", src_ip="10.0.10.55"),
        MockKerbEvent(cipher="aes256", service="CIFS/fs01", src_ip="10.0.10.55"),
        MockKerbEvent(cipher="aes256", service="HOST/dc01", src_ip="10.0.10.55"),
        MockKerbEvent(cipher="aes256", service="RPC/ex01", src_ip="10.0.10.55"),
        MockKerbEvent(cipher="aes128", service="ldap/dc02", src_ip="10.0.10.55"),  # 6th unique AES service!
    ]
    
    findings = list(detect_kerberos(events))
    assert len(findings) == 2 # 1 RC4 from .99, 1 AES Sweep from .55
    titles = [f.title for f in findings]
    assert "Kerberoasting (Weak Cipher RC4 Downgrade)" in titles
    assert "Kerberoasting (AES Service Sweep)" in titles


# ==============================================================================
# TIER 3: Absolute Schema Paradoxes & Dunder Overrides (12 Cases)
# ==============================================================================

class ExplodingObject:
    def __str__(self):
        raise ValueError("Boom")

class RecursiveDestructor:
    def __init__(self):
        self.loop = self
    def __str__(self):
        return "rc4"

SCHEMA_PAYLOADS = [
    ("bytearray_payload", bytearray(b"23"), 1),
    ("recursive_object", RecursiveDestructor(), 1),
    ("deep_json_dict_containing_signature", {"nested": {"cipher": "rc4"}}, 1), 
    ("deep_json_dict_benign", {"nested": {"cipher": "junk"}}, 0), 
    ("exploding_object", ExplodingObject(), 0),
    ("unexecuted_lambda", lambda x: x, 0),                        
    ("builtin_class", int, 0),                                
    ("exception_object", Exception("Inner error"), 0),
    ("null_value", None, 0),
    ("boolean_true", True, 0), 
]

@pytest.mark.parametrize(
    "name, hostile_type, expected_count", 
    SCHEMA_PAYLOADS,
    ids=[item[0] for item in SCHEMA_PAYLOADS]
)
def test_omni_type_coercion_survival(name: str, hostile_type: Any, expected_count: int) -> None:
    event = MockKerbEvent(cipher=hostile_type)
    findings = list(detect_kerberos([event]))
    assert len(findings) == expected_count

def test_aes_state_pollution():
    """Validates the AES dictionary tracker survives unhashable service names."""
    events = [
        # Passing an unhashable dict as the service name. 
        # The engine must safely coerce it to a string before adding to the set.
        MockKerbEvent(cipher="aes256", service={"unhashable": "dict"}),
        MockKerbEvent(cipher="aes256", service=["unhashable", "list"]),
    ]
    # If the engine fails to cast to string, this raises TypeError: unhashable type
    findings = list(detect_kerberos(events))
    assert len(findings) == 0


# ==============================================================================
# TIER 4: Network Topology Suppression (10 Cases)
# ==============================================================================

TOPOLOGY_PAYLOADS = [
    ("octal_loopback", "0177.0000.0000.0001", "127.0.0.1", 0),
    ("hex_loopback", "0x7f000001", "127.0.0.1", 0),
    ("llmnr_multicast", "224.0.0.252", "224.0.0.252", 0),
    ("aws_metadata_apipa", "169.254.169.254", "169.254.169.254", 0),
    ("ipv6_loopback", "::1", "::1", 0),
    ("ipv4_mapped_ipv6", "::ffff:127.0.0.1", "::ffff:127.0.0.1", 0),
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
    event = MockKerbEvent(src_ip=src, dst_ip=dst, cipher="rc4")
    findings = list(detect_kerberos([event]))
    assert len(findings) == expected_count


# ==============================================================================
# TIER 5: Hyper-Scale Generator Stability (1 Case)
# ==============================================================================

def test_hyperscale_100k_event_stream() -> None:
    def generate_hyperscale():
        for i in range(100_000):
            if i % 10_000 == 0:
                yield MockKerbEvent(request_type="TGS", cipher="rc4", uid=f"APT-{i}")
            else:
                yield MockKerbEvent(request_type="TGT", cipher="aes256", uid=f"NOISE-{i}")

    stream = detect_kerberos(generate_hyperscale())
    assert isinstance(stream, types.GeneratorType)
    
    findings = list(stream)
    assert len(findings) == 10
    assert findings[0].evidence_uids == ["APT-0"]