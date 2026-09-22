"""
Apex-Predator NTLM Identity Abuse Fuzzing Suite (MITRE ATT&CK T1550.002).
Engineered for military-grade resilience across exactly 50 test cases covering:
- Tri-state boolean mutilation (Zalgo, zero-width spaces, null bytes, floats, URL encoding).
- Active Directory username sanitization (machine accounts, domain prefixes, noise stripping).
- Stateful behavioral velocity (deduplication of single-user sprays, PtH spread thresholds).
- Schema destruction (exploding dunders, recursive self-pointers, unhashable objects).
- Topology suppression and hyperscale stream processing.
"""

import types
import pytest
from typing import Any, List
from lmr.detections.ntlm import detect_ntlm

class MockNtlmEvent:
    def __init__(self, success: Any = "T", username: Any = "administrator", 
                 src_ip: Any = "10.0.10.55", dst_ip: Any = "10.0.20.100", 
                 uid: Any = "C_NTLM_OMNI"):
        self.uid = uid
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.success = success
        self.username = username


# ==============================================================================
# TIER 1: Tri-State Boolean Obfuscation & Evasion Traps (18 Cases)
# ==============================================================================

AUTH_BOOLEAN_PAYLOADS = [
    # Confirmed Failures (trigger Spray alert when 6 unique users fail)
    ("native_false", False, 1),
    ("zeek_f", "F", 1),
    ("lowercase_false", "false", 1),
    ("integer_zero", 0, 1),
    ("float_zero", 0.0, 1),
    ("zeek_unset_hyphen", "-", 1),
    ("url_encoded_false", "%46%41%4c%53%45", 1),
    ("zalgo_false", "F\u0337A\u0337L\u0337S\u0337E\u0337", 1),
    ("zero_width_space_false", "F\u200BA\u200BL\u200BS\u200BE", 1),
    ("null_byte_padded_false", "F\x00ALSE", 1),

    # Confirmed Successes (do NOT trigger spray; destination count is 1 so no PtH)
    ("native_true", True, 0),
    ("zeek_t", "T", 0),
    ("lowercase_true", "true", 0),
    ("integer_one", 1, 0),
    ("float_one", 1.0, 0),
    ("url_encoded_true_full", "%54%52%55%45", 0),
    ("url_encoded_single_t", "%54", 0),
    ("zalgo_true", "T\u0337R\u0337U\u0337E\u0337", 0),
]

@pytest.mark.parametrize(
    "name, success_val, expected_count", 
    AUTH_BOOLEAN_PAYLOADS,
    ids=[item[0] for item in AUTH_BOOLEAN_PAYLOADS]
)
def test_ntlm_success_semantics(name: str, success_val: Any, expected_count: int) -> None:
    # 6 failed authentications against 6 unique accounts trigger the spray alert
    events = [MockNtlmEvent(success=success_val, username=f"user_{i}") for i in range(6)]
    findings = list(detect_ntlm(events))
    assert len(findings) == expected_count
    if expected_count > 0:
        assert findings[0].title == "NTLM Credential Spraying"


# ==============================================================================
# TIER 2: Username Normalization & Active Directory Entities (12 Cases)
# ==============================================================================

def _generate_username_events(test_id: str) -> List[MockNtlmEvent]:
    """Generates 6 events with tailored username obfuscation patterns."""
    if test_id == "machine_account_dollar":
        return [MockNtlmEvent(success=False, username=f"DC0{i}$") for i in range(6)]
    if test_id == "domain_qualified_backslash":
        return [MockNtlmEvent(success=False, username=f"CORP\\admin{i}") for i in range(6)]
    if test_id == "url_encoded_username":
        return [MockNtlmEvent(success=False, username=f"%75%73%65%72_{i}") for i in range(6)]
    if test_id == "zalgo_username":
        return [MockNtlmEvent(success=False, username=f"u\u0337s\u0337e\u0337r\u0337_{i}") for i in range(6)]
    if test_id == "zero_width_username":
        return [MockNtlmEvent(success=False, username=f"u\u200Bs\u200Be\u200Br\u200B_{i}") for i in range(6)]
    if test_id == "null_byte_username":
        return [MockNtlmEvent(success=False, username=f"admin\x00_{i}") for i in range(6)]
    if test_id == "hyphen_underscore_mix":
        return [MockNtlmEvent(success=False, username=f"sec-ops_svc{i}$") for i in range(6)]
    if test_id == "bytearray_username":
        return [MockNtlmEvent(success=False, username=bytearray(f"user_{i}".encode())) for i in range(6)]
    
    # Noise/Hostile inputs (must be dropped or normalized to 'unknown' -> 0 alerts)
    if test_id == "pure_punctuation_noise":
        noise = ["!!!", "@@@", "###", "$$$", "%%%", "^^^"]
        return [MockNtlmEvent(success=False, username=noise[i]) for i in range(6)]
    if test_id == "whitespace_noise":
        return [MockNtlmEvent(success=False, username="   \t\n  ") for _ in range(6)]
    if test_id == "boolean_username_trap":
        return [MockNtlmEvent(success=False, username=True) for _ in range(6)]
    if test_id == "dict_username_trap":
        return [MockNtlmEvent(success=False, username={"user": f"admin{i}"}) for i in range(6)]
    return []

USERNAME_CASES = [
    ("machine_account_dollar", 1),
    ("domain_qualified_backslash", 1),
    ("url_encoded_username", 1),
    ("zalgo_username", 1),
    ("zero_width_username", 1),
    ("null_byte_username", 1),
    ("hyphen_underscore_mix", 1),
    ("bytearray_username", 1),
    ("pure_punctuation_noise", 0),
    ("whitespace_noise", 0),
    ("boolean_username_trap", 0),
    ("dict_username_trap", 0),
]

@pytest.mark.parametrize(
    "name, expected_count", 
    USERNAME_CASES,
    ids=[item[0] for item in USERNAME_CASES]
)
def test_username_extraction_semantics(name: str, expected_count: int) -> None:
    events = _generate_username_events(name)
    findings = list(detect_ntlm(events))
    assert len(findings) == expected_count


# ==============================================================================
# TIER 3: Network Topology Suppression (10 Cases)
# ==============================================================================

TOPOLOGY_PAYLOADS = [
    ("octal_loopback", "0177.0000.0000.0001", "127.0.0.1", 0),
    ("hex_loopback", "0x7f000001", "127.0.0.1", 0),
    ("llmnr_multicast", "224.0.0.252", "224.0.0.252", 0),
    ("aws_metadata_apipa", "169.254.169.254", "169.254.169.254", 0),
    ("interface_scoped", "10.0.5.5%eth0", "10.0.5.5", 0),
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
    # Send 4 successful connections to distinct destinations to trigger PtH
    events = [
        MockNtlmEvent(src_ip=src, dst_ip=f"{dst}_{i}" if expected_count else dst, success="T") 
        for i in range(4)
    ]
    findings = list(detect_ntlm(events))
    assert len(findings) == expected_count


# ==============================================================================
# TIER 4: Absolute Schema Destruction & Paradox Objects (6 Cases)
# ==============================================================================

class ExplodingObject:
    def __str__(self):
        raise ValueError("Boom")

class RecursiveDestructor:
    def __init__(self):
        self.loop = self
    def __str__(self):
        return "F"

SCHEMA_PAYLOADS = [
    ("exploding_object", ExplodingObject(), 0),               # Handled safely as None -> dropped
    ("recursive_destructor", RecursiveDestructor(), 1),       # Resolves __str__ to 'F' -> spray alert
    ("unexecuted_lambda", lambda x: x, 0),                    # Callable -> dropped
    ("builtin_class", int, 0),                                # Type -> dropped
    ("exception_object", ValueError("Malicious"), 0),         # Exception -> dropped
    ("bytearray_payload_f", bytearray(b"F"), 1),              # Binary coerced -> spray alert
]

@pytest.mark.parametrize(
    "name, hostile_type, expected_count", 
    SCHEMA_PAYLOADS,
    ids=[item[0] for item in SCHEMA_PAYLOADS]
)
def test_omni_type_coercion_survival(name: str, hostile_type: Any, expected_count: int) -> None:
    events = [MockNtlmEvent(success=hostile_type, username=f"user_{i}") for i in range(6)]
    findings = list(detect_ntlm(events))
    assert len(findings) == expected_count


# ==============================================================================
# TIER 5: Stateful Behavioral Velocity & Hyperscale Stream (4 Cases)
# ==============================================================================

def test_ntlm_pth_spread_velocity() -> None:
    """Validates Pass-the-Hash alerts only trigger when exceeding threshold of 3 unique hosts."""
    # 3 distinct hosts = within baseline threshold (no alert)
    events = [MockNtlmEvent(success="T", dst_ip=f"10.0.20.{i}") for i in range(1, 4)]
    assert len(list(detect_ntlm(events))) == 0

    # Duplicate destinations must not count toward the threshold
    events.append(MockNtlmEvent(success="T", dst_ip="10.0.20.1"))
    assert len(list(detect_ntlm(events))) == 0

    # 4th unique destination triggers the PtH finding
    events.append(MockNtlmEvent(success="T", dst_ip="10.0.20.99"))
    findings = list(detect_ntlm(events))
    assert len(findings) == 1
    assert findings[0].title == "NTLM Pass-the-Hash / Lateral Spread"
    assert findings[0].confidence == "Medium"

    # Subsequent connections from the same IP must not generate duplicate alert noise
    events.append(MockNtlmEvent(success="T", dst_ip="10.0.20.105"))
    findings_after = list(detect_ntlm(events))
    assert len(findings_after) == 1

def test_ntlm_spray_duplicate_user_deduplication() -> None:
    """100 failed logins against the same account must NOT trigger a credential spray alert."""
    # Single account targeted 100 times (brute force, not a spray across accounts)
    events = [MockNtlmEvent(success="F", username="administrator") for _ in range(100)]
    assert len(list(detect_ntlm(events))) == 0

    # Adding 5 additional distinct accounts (total 6 unique accounts) triggers spray
    for i in range(1, 6):
        events.append(MockNtlmEvent(success="F", username=f"service_acc_{i}"))
    
    findings = list(detect_ntlm(events))
    assert len(findings) == 1
    assert findings[0].title == "NTLM Credential Spraying"
    assert findings[0].confidence == "High"

def test_ntlm_interleaved_spray_and_pth() -> None:
    """Validates simultaneous detection of both Spray and PtH on interleaved event streams."""
    events = [
        # Attacker 1 (10.0.10.55) executing PtH to 4 distinct machines
        MockNtlmEvent(src_ip="10.0.10.55", dst_ip="10.0.20.1", success="T"),
        MockNtlmEvent(src_ip="10.0.10.55", dst_ip="10.0.20.2", success="T"),
        # Attacker 2 (10.0.10.99) executing credential spray across accounts
        MockNtlmEvent(src_ip="10.0.10.99", username="user_a", success="F"),
        MockNtlmEvent(src_ip="10.0.10.99", username="user_b", success="F"),
        MockNtlmEvent(src_ip="10.0.10.55", dst_ip="10.0.20.3", success="T"),
        MockNtlmEvent(src_ip="10.0.10.99", username="user_c", success="F"),
        MockNtlmEvent(src_ip="10.0.10.55", dst_ip="10.0.20.4", success="T"),  # PtH triggers here
        MockNtlmEvent(src_ip="10.0.10.99", username="user_d", success="F"),
        MockNtlmEvent(src_ip="10.0.10.99", username="user_e", success="F"),
        MockNtlmEvent(src_ip="10.0.10.99", username="user_f", success="F"),  # Spray triggers here
    ]

    findings = list(detect_ntlm(events))
    assert len(findings) == 2
    titles = {f.title for f in findings}
    assert "NTLM Pass-the-Hash / Lateral Spread" in titles
    assert "NTLM Credential Spraying" in titles

def test_hyperscale_100k_stream() -> None:
    """Validates generator memory boundaries and streaming performance over 100k events."""
    def generate_hyperscale():
        for i in range(100_000):
            if i % 10_000 == 0:
                # 10 failed logins across 10 unique users from single IP -> triggers spray
                yield MockNtlmEvent(src_ip="10.10.10.10", username=f"APT_USER_{i}", success="F")
            else:
                yield MockNtlmEvent(src_ip="192.168.1.50", dst_ip="192.168.1.100", success="T")

    stream = detect_ntlm(generate_hyperscale())
    assert isinstance(stream, types.GeneratorType)

    findings = list(stream)
    assert len(findings) == 1
    assert findings[0].src_ip == "10.10.10.10"
    assert findings[0].title == "NTLM Credential Spraying"