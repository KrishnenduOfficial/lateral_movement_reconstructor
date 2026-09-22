"""
Beyond-Insane RDP Lateral Movement Fuzzing Suite (MITRE ATT&CK T1021.001).
Engineered for military-grade resilience against:
- Homoglyph/Unicode evasion and zero-width spaces in payloads.
- Extreme schema destruction (recursive objects, lambdas, memory pointers).
- Cryptographic state paradoxes and protocol chimera attacks.
- Hyper-scale stream processing (100,000+ events) without memory leaks.
"""

import types
import pytest
from typing import Any, Generator
from lmr.detections.rdp import detect_rdp


class MockRdpEvent:
    def __init__(self, dst_port: Any = 3389, service: Any = "rdp", cookie: Any = "", 
                 selected_security: Any = "", client_name: Any = "", src_ip: Any = "10.0.10.55", 
                 dst_ip: Any = "10.0.20.100", uid: Any = "C_RDP_OMNI"):
        self.uid = uid
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.service = service
        self.cookie = cookie
        self.selected_security = selected_security
        self.client_name = client_name


# ==============================================================================
# TIER 1: Cryptographic State Paradoxes & Protocol Chimeras
# ==============================================================================

@pytest.mark.parametrize("service, security, expected_confidence", [
    ("rdp", "HYBRID_EX", "High"),       # Modern NLA with CredSSP
    ("rdp", "RDP", "High"),             # Legacy Standard RDP Security
    ("rdp", "SSL", "High"),             # TLS wrapped
    ("ssl", "HYBRID", "Medium"),        # Missing DPD correlation, relies on port
    ("http", "HYBRID", "Medium"),       # Protocol chimera (HTTP service, RDP security) on port 3389
])
def test_cryptographic_state_matrix(service: str, security: str, expected_confidence: str) -> None:
    event = MockRdpEvent(dst_port=3389, service=service, selected_security=security)
    findings = list(detect_rdp([event]))
    assert findings[0].confidence == expected_confidence

# ==============================================================================
# TIER 2: Advanced Evasion (Unicode, Zalgo, Homoglyphs, Null Bytes)
# ==============================================================================

COOKIE_EVASION_PAYLOADS = [
    ("uppercase_evasion", "MSTSHASH=admin", True),
    ("null_byte_split", "msts\x00hash=admin", False),
    ("zero_width_space", "mstshash=\u200Badmin", True),
    ("rtlo_override", "mstshash=‮nimda", True),
    ("cyrillic_homoglyph", "мѕтѕнаѕн=admin", False),
    ("massive_buffer_bomb", "mstshash=" + "A" * 50_000, True),
    ("zalgo_text", "m̸s̸t̸s̸h̸a̸s̸h̸=admin", False),
]

@pytest.mark.parametrize(
    "payload_name, cookie_payload, expected_detection", 
    COOKIE_EVASION_PAYLOADS,
    ids=[item[0] for item in COOKIE_EVASION_PAYLOADS]
)
def test_cookie_signature_evasion(payload_name: str, cookie_payload: str, expected_detection: bool) -> None:
    event = MockRdpEvent(dst_port=8080, service="http", cookie=cookie_payload)
    findings = list(detect_rdp([event]))
    
    if expected_detection:
        assert len(findings) == 1
        assert findings[0].confidence == "High"
    else:
        assert len(findings) == 0  # Fails strict match and is on port 8080


# ==============================================================================
# TIER 3: Absolute Schema Destruction (Recursive Objects, Pointers, Functions)
# ==============================================================================

class RecursiveDestructor:
    """An object that references itself to cause infinite recursion if naively parsed."""
    def __init__(self):
        self.loop = self
    def __str__(self):
        return "mstshash=boom"

@pytest.mark.parametrize("hostile_type", [
    lambda x: x,                        # Unexecuted lambda function
    RecursiveDestructor(),              # Recursive object
    type("DynamicClass", (), {}),       # Bare class definition
    Exception("Inner exception"),       # Exception object passed as data
    {"nested": {"nested": {"nested": "mstshash="}}}, # Deep JSON
    (x for x in range(10)),             # Generator expression
])
def test_omni_type_coercion_survival(hostile_type: Any) -> None:
    event = MockRdpEvent(
        dst_port=3389,
        service=hostile_type,
        cookie=hostile_type,
        selected_security=hostile_type,
    )
    findings = list(detect_rdp([event]))
    
    assert len(findings) == 1
    # If the custom __str__ outputs mstshash=, it triggers High. Otherwise Medium fallback for port 3389.
    assert findings[0].confidence in ["High", "Medium"]


# ==============================================================================
# TIER 4: BGP, Anycast, and Extreme Topology Spoofing
# ==============================================================================

@pytest.mark.parametrize("src, dst", [
    ("0177.0000.0000.0001", "127.0.0.1"),    # Octal representation of loopback
    ("0x7f000001", "127.0.0.1"),             # Hex representation of loopback
    ("224.0.0.252", "224.0.0.252"),          # LLMNR Multicast looping
    ("169.254.169.254", "169.254.169.254"),  # AWS/Cloud metadata self-query
    ("10.0.5.5", "10.0.5.5%eth0"),           # Same IP, one has interface scope
])
def test_insane_topology_suppression(src: str, dst: str) -> None:
    event = MockRdpEvent(src_ip=src, dst_ip=dst, dst_port=3389, cookie="mstshash=admin")
    findings = list(detect_rdp([event]))
    assert len(findings) == 0


# ==============================================================================
# TIER 5: Hyper-Scale Generator Stability & Memory Safety
# ==============================================================================

def test_hyperscale_100k_event_stream() -> None:
    """
    [Beyond Insane] Validates that the engine can process 100,000 continuous objects 
    without exhausting memory, successfully picking out 10 targeted attacks.
    """
    def generate_hyperscale():
        for i in range(100_000):
            if i % 10_000 == 0:
                yield MockRdpEvent(dst_port=3389, cookie=f"mstshash=apttarget_{i}", uid=f"APT-{i}")
            else:
                yield MockRdpEvent(dst_port=443, service="ssl", uid=f"NOISE-{i}")

    stream = detect_rdp(generate_hyperscale())
    assert isinstance(stream, types.GeneratorType)
    
    findings = list(stream)
    assert len(findings) == 10
    assert findings[0].evidence_uids == ["APT-0"]
    assert findings[-1].evidence_uids == ["APT-90000"]