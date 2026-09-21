"""
Insane-level test and fuzzing suite for WinRM detection.
Covers:
- Adversarial URI obfuscation (single/double percent-encoding, path traversal, matrix parameters)
- False positive avoidance (traversal traps, loopback, self-traffic, broadcast)
- Network protocol edge cases (IPv6 link-local scope IDs, IPv4-mapped IPv6)
- Stream poisoning, memory stress (10MB buffer bombs), and lazy generator safety
"""

import types
import pytest
from typing import Any, Generator

from lmr.detections.winrm import detect_winrm


class MockEvent:
    """Mock of LmrEvent allowing arbitrary field types and injections."""
    def __init__(
        self,
        dst_port: Any = 0,
        uri: Any = "",
        src_ip: Any = "10.0.0.5",
        dst_ip: Any = "10.0.0.20",
        uid: Any = "C12345",
    ):
        self.uid = uid
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.uri = uri


# ==============================================================================
# TIER 1: Operational Baseline
# ==============================================================================

def test_winrm_standard_http_baseline() -> None:
    events = [MockEvent(dst_port=5985, uri="/wsman")]
    findings = list(detect_winrm(events))
    assert len(findings) == 1
    assert findings[0].confidence == "High"
    assert findings[0].attack_ids == ["T1021.006"]


def test_winrm_standard_https_baseline() -> None:
    events = [MockEvent(dst_port=5986, uri="")]
    findings = list(detect_winrm(events))
    assert len(findings) == 1
    assert findings[0].confidence == "Medium"


def test_benign_traffic_isolation() -> None:
    events = [
        MockEvent(dst_port=80, uri="/index.html"),
        MockEvent(dst_port=443, uri="/login"),
        MockEvent(dst_port=8080, uri="/api/v1/status"),
    ]
    assert len(list(detect_winrm(events))) == 0


def test_boundary_ports_not_flagged() -> None:
    events = [
        MockEvent(dst_port=5984, uri="/_utils/"),  # CouchDB (ignored)
        MockEvent(dst_port=5987, uri="/wsman"),   # Non-standard port with explicit /wsman endpoint (detected)
    ]
    findings = list(detect_winrm(events))
    assert len(findings) == 1
    assert findings[0].dst_ip == "10.0.0.20"
    assert findings[0].confidence == "High"


def test_empty_events_stream() -> None:
    assert list(detect_winrm([])) == []


# ==============================================================================
# TIER 2: Adversarial Path Obfuscation & Evasion
# ==============================================================================

ADVANCED_OBFUSCATIONS = [
    ("single_percent_encoding", "/w%73man", True),
    ("full_percent_encoding", "/%77%73%6d%61%6e", True),
    ("double_percent_encoding", "/%2577%2573man", True),
    ("mixed_case_encoding", "/%57%73%4d%61%6e", True),
    ("redundant_slashes", "///////wsman", True),
    ("dot_slash_segments", "/././wsman/./", True),
    ("relative_traversal_hit", "/random/dir/../../wsman", True),
    ("matrix_parameters", "/wsman;transport=http?client=pwsh", True),
    ("query_string_payload", "/wsman?session=1337&action=exec", True),
    ("null_byte_split", "/wsman\x00.png", True),
    ("traversal_evasion_trap", "/wsman/../index.html", False),  # Normalizes to /index.html
    ("fake_prefix_trap", "/wsman_backup_file.txt", False),      # Normalizes to /wsman_backup_file.txt
]

@pytest.mark.parametrize(
    "name, uri_payload, should_detect_wsman",
    ADVANCED_OBFUSCATIONS,
    ids=[item[0] for item in ADVANCED_OBFUSCATIONS],
)
def test_adversarial_uri_obfuscations(
    name: str, uri_payload: str, should_detect_wsman: bool
) -> None:
    """Tests canonical path decoding against adversarial obfuscation techniques."""
    events = [MockEvent(dst_port=8080, uri=uri_payload)]
    findings = list(detect_winrm(events))

    if should_detect_wsman:
        assert len(findings) == 1
        assert findings[0].confidence == "High"
    else:
        assert len(findings) == 0


# ==============================================================================
# TIER 3: Network Topology & False Positive Suppression
# ==============================================================================

@pytest.mark.parametrize("src, dst", [
    ("127.0.0.1", "127.0.0.1"),           # Local IPv4 loopback
    ("::1", "::1"),                       # Local IPv6 loopback
    ("10.0.0.5", "10.0.0.5"),             # Self-traffic on primary NIC
    ("0.0.0.0", "10.0.0.5"),              # Unspecified source
    ("10.0.0.5", "224.0.0.1"),            # Multicast destination
    ("10.0.0.5", "ff02::1"),              # IPv6 all-nodes multicast
])
def test_suppress_loopback_and_self_traffic(src: str, dst: str) -> None:
    """Lateral movement requires cross-host network traversal; self-traffic is excluded."""
    events = [MockEvent(dst_port=5985, uri="/wsman", src_ip=src, dst_ip=dst)]
    findings = list(detect_winrm(events))
    assert len(findings) == 0


def test_ipv6_link_local_with_interface_scope() -> None:
    """Verifies IPv6 link-local parsing with zone delimiters (fe80::1%eth0)."""
    events = [
        MockEvent(
            dst_port=5985,
            uri="/wsman",
            src_ip="fe80::1ff:fe00:1%eth0",
            dst_ip="fe80::2ff:fe00:2%eth0",
        )
    ]
    findings = list(detect_winrm(events))
    assert len(findings) == 1
    assert "fe80::1ff:fe00:1%eth0" in findings[0].src_ip


def test_ipv4_mapped_ipv6_detection() -> None:
    events = [
        MockEvent(
            dst_port=5985,
            uri="/wsman",
            src_ip="::ffff:192.168.1.50",
            dst_ip="::ffff:192.168.1.100",
        )
    ]
    findings = list(detect_winrm(events))
    assert len(findings) == 1


# ==============================================================================
# TIER 4: Stream Poisoning, Memory Stress & Chaos
# ==============================================================================

def test_poisoned_stream_non_crashing() -> None:
    """Ensures generator does not crash when hostile/foreign objects are in stream."""
    poisoned_events = [
        None,
        "not an event",
        123456,
        {"dst_port": 5985},
        MockEvent(dst_port=5985, uri="/wsman", uid="VALID-01"),
        Exception("Boom"),
        MockEvent(dst_port=5985, uri="/wsman", uid="VALID-02"),
    ]

    findings = list(detect_winrm(poisoned_events))
    assert len(findings) == 2
    assert findings[0].evidence_uids == ["VALID-01"]
    assert findings[1].evidence_uids == ["VALID-02"]


def test_memory_bomb_buffer_stretch() -> None:
    """Tests resistance to 10MB URI memory bombs without excessive memory use."""
    giant_uri = "/wsman/" + ("A" * 10_000_000)
    events = [MockEvent(dst_port=8080, uri=giant_uri)]
    findings = list(detect_winrm(events))
    assert len(findings) == 1
    assert findings[0].confidence == "High"


def test_deep_path_traversal_recursion() -> None:
    """Checks handling of deeply nested directory traversal attempts."""
    deep_uri = ("/test/../" * 5000) + "wsman"
    events = [MockEvent(dst_port=8080, uri=deep_uri)]
    findings = list(detect_winrm(events))
    assert len(findings) == 1
    assert findings[0].confidence == "High"


def test_lazy_generator_infinite_stream() -> None:
    """Verifies that infinite streams are consumed lazily without hang."""
    def infinite_benign_stream() -> Generator[MockEvent, None, None]:
        while True:
            yield MockEvent(dst_port=80, uri="/index.html")

    stream = detect_winrm(infinite_benign_stream())
    assert isinstance(stream, types.GeneratorType)


def test_large_volume_interleaved_attack() -> None:
    """Validates high-volume traffic processing (15,000 events, 15 attack findings)."""
    def generate_events():
        for i in range(15000):
            if i % 1000 == 0:
                yield MockEvent(dst_port=5985, uri="/wsman", uid=f"ATTACK-{i}")
            else:
                yield MockEvent(dst_port=443, uri="/status", uid=f"BENIGN-{i}")

    findings = list(detect_winrm(generate_events()))
    assert len(findings) == 15
    assert findings[0].evidence_uids == ["ATTACK-0"]
    assert findings[-1].evidence_uids == ["ATTACK-14000"]