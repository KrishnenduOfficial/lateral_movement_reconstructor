"""
Apex-Predator SSH Lateral Movement Fuzzing Suite (MITRE ATT&CK T1021.004).
Engineered for military-grade resilience against:
- Zalgo text, zero-width spaces, and deep regex obfuscation.
- Scientific notation, NaN/Infinity math bombs, and overflow attacks.
- Dunder method paradoxes (__str__ vs __bool__ conflicts).
- Malicious exception injection during type coercion.
"""

import types
import pytest
import math
from typing import Any, Generator
from lmr.detections.ssh import detect_ssh

class MockSshEvent:
    def __init__(self, auth_success: Any = "T", auth_attempts: Any = 1, 
                 src_ip: Any = "10.0.10.55", dst_ip: Any = "10.0.20.100", uid: Any = "C_SSH_OMNI"):
        self.uid = uid
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.auth_success = auth_success
        self.auth_attempts = auth_attempts


# ==============================================================================
# TIER 1: Extreme Boolean Obfuscation & Regex Evasion (18 Cases)
# ==============================================================================

AUTH_PAYLOADS = [
    ("native_true", True, 1, 1, "Medium"),
    ("native_false", False, 1, 0, "None"),
    ("zeek_t", "T", 1, 1, "Medium"),
    ("url_encoded", "%54%52%55%45", 1, 1, "Medium"),              # %54%52%55%45 = TRUE
    ("zero_width_space", "T\u200BR\u200BU\u200BE", 1, 1, "Medium"),
    ("zalgo_text", "T̷R̷U̷E̷", 1, 1, "Medium"),                        # Regex must crush the Zalgo
    ("null_byte_padded", "T\x00RUE", 1, 1, "Medium"),
    ("punctuation_noise", "![T.R.U.E]!", 1, 1, "Medium"),         # Should reduce to TRUE
    ("massive_padding", " " * 5000 + "T" + " " * 5000, 1, 1, "Medium"),
    ("array_cast_true", ["T"], 1, 1, "Medium"),                   # str(['T']) = "['T']" -> "T" -> True
    ("array_cast_false", ["F"], 1, 0, "None"),
    ("integer_one", 1, 1, 1, "Medium"),
    ("integer_zero", 0, 1, 0, "None"),
    ("string_one", "1", 1, 1, "Medium"),
    ("yes_string", "yes", 1, 1, "Medium"),
    ("zeek_unset", "-", 1, 0, "None"),
    ("corrupted_bool", "TRU", 1, 0, "None"),                      # Incomplete string, should fail
    ("dict_injection", {"status": "T"}, 1, 0, "None"),            # str(dict) yields 'STATUST', not 'T'
]

@pytest.mark.parametrize(
    "name, success_val, attempts_val, expected_count, expected_confidence", 
    AUTH_PAYLOADS,
    ids=[item[0] for item in AUTH_PAYLOADS]
)
def test_auth_success_semantics(name: str, success_val: Any, attempts_val: Any, expected_count: int, expected_confidence: str) -> None:
    event = MockSshEvent(auth_success=success_val, auth_attempts=attempts_val)
    findings = list(detect_ssh([event]))
    assert len(findings) == expected_count
    if expected_count > 0:
        assert findings[0].confidence == expected_confidence


# ==============================================================================
# TIER 2: Mathematical Explosives & Integer Mutilation (12 Cases)
# ==============================================================================

ATTEMPT_PAYLOADS = [
    ("five_attempts", 5, "Medium"),         
    ("brute_force_six", 6, "High"),         
    ("scientific_notation", "1e1", "High"),        # 1e1 = 10.0 -> 10 (High)
    ("positive_sign_float", "+6.000", "High"),     # +6.000 -> 6 (High)
    ("negative_attempts", -5, "Medium"),           # -5 is not > 5
    ("nan_string", "nan", "Medium"),               # Should safely default to 0
    ("inf_string", "inf", "Medium"),               # Should safely default to 0
    ("native_nan_float", float('nan'), "Medium"),  # math.isnan check
    ("native_inf_float", float('inf'), "Medium"),  # math.isinf check
    ("hex_string", "0x0A", "Medium"),              # float("0x0A") raises ValueError -> 0 -> Medium
    ("google_scale_int", 10**100, "High"),         # Massive integer
    ("corrupted_text_int", "ten", "Medium"),       # Fails cast -> defaults to 0
]

@pytest.mark.parametrize(
    "name, attempts_val, expected_confidence", 
    ATTEMPT_PAYLOADS,
    ids=[item[0] for item in ATTEMPT_PAYLOADS]
)
def test_auth_attempts_heuristics(name: str, attempts_val: Any, expected_confidence: str) -> None:
    event = MockSshEvent(auth_success="T", auth_attempts=attempts_val)
    findings = list(detect_ssh([event]))
    assert len(findings) == 1
    assert findings[0].confidence == expected_confidence


# ==============================================================================
# TIER 3: Absolute Schema Paradoxes & Dunder Overrides (12 Cases)
# ==============================================================================

class LiarObject:
    """Tells Python it is False, but its string representation is TRUE."""
    def __bool__(self):
        return False
    def __str__(self):
        return "TRUE"

class ExplodingObject:
    """Raises an exception the moment you try to cast it to a string."""
    def __str__(self):
        raise ValueError("Boom")

SCHEMA_PAYLOADS = [
    ("dunder_liar_success", LiarObject(), 1, 1, "Medium"),       # Engine trusts __str__ over __bool__
    ("exploding_success", ExplodingObject(), 1, 0, "None"),      # Engine catches the exception and drops
    ("bytearray_payload", bytearray(b"TRUE"), 1, 1, "Medium"),
    ("memoryview_payload", memoryview(b"1"), 1, 1, "Medium"),
    ("unexecuted_lambda", lambda x: x, 1, 0, "None"),                        
    ("builtin_class", int, 1, 0, "None"),                                
    ("null_value", None, 1, 0, "None"),
    
    # Passing the paradoxes into the attempt count field instead of success field
    ("dunder_liar_attempts", "T", LiarObject(), 1, "Medium"),    # float("TRUE") fails -> 0 attempts
    ("exploding_attempts", "T", ExplodingObject(), 1, "Medium"), # Exception caught -> 0 attempts
    ("memoryview_attempts", "T", memoryview(b"6"), 1, "High"),
    ("bytearray_attempts", "T", bytearray(b"1e2"), 1, "High"),
]

@pytest.mark.parametrize(
    "name, success_val, attempts_val, expected_count, expected_confidence", 
    SCHEMA_PAYLOADS,
    ids=[item[0] for item in SCHEMA_PAYLOADS]
)
def test_omni_type_coercion_survival(name: str, success_val: Any, attempts_val: Any, expected_count: int, expected_confidence: str) -> None:
    event = MockSshEvent(auth_success=success_val, auth_attempts=attempts_val)
    findings = list(detect_ssh([event]))
    assert len(findings) == expected_count
    if expected_count > 0:
        assert findings[0].confidence == expected_confidence


# ==============================================================================
# TIER 4: Network Topology Suppression (10 Cases)
# ==============================================================================

TOPOLOGY_PAYLOADS = [
    ("octal_loopback", "0177.0000.0000.0001", "127.0.0.1", 0),
    ("hex_loopback", "0x7f000001", "127.0.0.1", 0),
    ("llmnr_multicast", "224.0.0.252", "224.0.0.252", 0),
    ("aws_metadata_apipa", "169.254.169.254", "169.254.169.254", 0),
    ("interface_scoped", "10.0.5.5", "10.0.5.5%eth0", 0),
    ("ipv6_loopback", "::1", "::1", 0),
    ("ipv4_mapped_ipv6", "::ffff:127.0.0.1", "::ffff:127.0.0.1", 0),
    ("same_private_ip", "192.168.1.1", "192.168.1.1", 0),
    ("valid_lateral_ipv4", "10.0.10.55", "10.0.20.100", 1),       
    ("valid_cgnat_lateral", "100.64.0.5", "100.64.0.6", 1),       
]

@pytest.mark.parametrize(
    "name, src, dst, expected_count", 
    TOPOLOGY_PAYLOADS,
    ids=[item[0] for item in TOPOLOGY_PAYLOADS]
)
def test_topology_suppression(name: str, src: str, dst: str, expected_count: int) -> None:
    event = MockSshEvent(src_ip=src, dst_ip=dst, auth_success="T")
    findings = list(detect_ssh([event]))
    assert len(findings) == expected_count


# ==============================================================================
# TIER 5: Hyper-Scale Generator Stability (1 Case)
# ==============================================================================

def test_hyperscale_100k_event_stream() -> None:
    def generate_hyperscale():
        for i in range(100_000):
            if i % 10_000 == 0:
                yield MockSshEvent(auth_success="T", auth_attempts=6, uid=f"APT-{i}")
            else:
                yield MockSshEvent(auth_success="F", auth_attempts=1, uid=f"NOISE-{i}")

    stream = detect_ssh(generate_hyperscale())
    assert isinstance(stream, types.GeneratorType)
    
    findings = list(stream)
    assert len(findings) == 10
    assert findings[0].evidence_uids == ["APT-0"]
    assert findings[-1].evidence_uids == ["APT-90000"]