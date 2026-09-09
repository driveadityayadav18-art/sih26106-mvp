"""
Tests for Tor exit node and proxy tagging anonymizer service.
"""

import pytest
from backend.services.geo_ip import (
    TOR_EXIT_NODES,
    load_tor_exit_nodes,
    detect_anonymizer,
    is_tor_exit_node,
    is_datacenter_proxy,
    enrich_ip,
)
from backend.parser.email_parser import EmailParser
from backend.parser.models import ReceivedHop


def test_tor_exit_nodes_loaded():
    """Verify that at least 50 real Tor exit nodes are loaded from tor_exit_nodes.txt."""
    nodes = load_tor_exit_nodes()
    assert len(nodes) >= 50
    assert "185.220.101.5" in nodes
    assert "185.220.100.241" in nodes
    assert "109.70.100.35" in nodes


def test_tor_exit_node_detection():
    """Verify that Tor exit nodes return high-confidence Tor detection."""
    test_ips = ["185.220.101.5", "185.220.100.241", "109.70.100.35", "171.25.193.20"]
    for ip in test_ips:
        assert is_tor_exit_node(ip) is True
        res = detect_anonymizer(ip)
        assert res["is_tor"] is True
        assert res["is_proxy"] is True
        assert res["confidence_score"] == 0.95
        assert res["anonymizer_type"] == "TOR Exit Node"


def test_datacenter_proxy_detection():
    """Verify that known cloud hosting/datacenter IPs are classified as Public VPN / Proxy."""
    # DigitalOcean range 159.65.0.0/16
    res_do = detect_anonymizer("159.65.120.45")
    assert res_do["is_tor"] is False
    assert res_do["is_proxy"] is True
    assert res_do["confidence_score"] == 0.70
    assert res_do["anonymizer_type"] == "Public VPN / Proxy"

    # Hetzner range 88.198.0.0/16
    res_hz = detect_anonymizer("88.198.40.12")
    assert res_hz["is_tor"] is False
    assert res_hz["is_proxy"] is True
    assert res_hz["confidence_score"] == 0.70
    assert res_hz["anonymizer_type"] == "Public VPN / Proxy"


def test_standard_residential_ip():
    """Verify that standard public IPs have low anonymizer confidence."""
    # Standard public IP not in Tor or DC range
    res = detect_anonymizer("93.184.216.34")
    assert res["is_tor"] is False
    assert res["is_proxy"] is False
    assert res["confidence_score"] == 0.10
    assert res["anonymizer_type"] == "None"


def test_private_and_invalid_ips():
    """Verify private/reserved/invalid IPs return score 0.0 and None."""
    for ip in ["10.0.0.1", "192.168.1.1", "127.0.0.1", "invalid-ip", "", None]:
        res = detect_anonymizer(ip)
        assert res["is_tor"] is False
        assert res["is_proxy"] is False
        assert res["confidence_score"] == 0.0
        assert res["anonymizer_type"] == "None"


def test_received_hop_model_serialization():
    """Verify ReceivedHop dataclass fields and to_dict serialization."""
    hop = ReceivedHop(
        index=1,
        raw="Received: from tor-node [185.220.101.5]",
        from_ip="185.220.101.5",
        is_tor=True,
        is_proxy=True,
        anonymizer_type="TOR Exit Node",
        confidence_score=0.95,
    )
    d = hop.to_dict()
    assert d["is_tor"] is True
    assert d["is_proxy"] is True
    assert d["anonymizer_type"] == "TOR Exit Node"
    assert d["confidence_score"] == 0.95


def test_email_parser_enriches_tor_hop():
    """Verify EmailParser detects Tor exit node in Received headers."""
    raw_email = (
        b"From: suspicious@anonymous.example\r\n"
        b"To: victim@example.test\r\n"
        b"Subject: Phishing attempt via Tor relay\r\n"
        b"Received: from exit-node.torproject.org ([185.220.101.5]) by mx.victim.example with ESMTP id 123; Tue, 01 Jan 2026 10:00:00 +0000\r\n"
        b"\r\n"
        b"Please click http://phishing.example to claim your prize."
    )
    result = EmailParser().parse(raw_email)
    assert len(result.trace.hops) == 1
    hop = result.trace.hops[0]
    assert hop.from_ip == "185.220.101.5"
    assert hop.is_tor is True
    assert hop.is_proxy is True
    assert hop.anonymizer_type == "TOR Exit Node"
    assert hop.confidence_score == 0.95

    serialized = hop.to_dict()
    assert serialized["is_tor"] is True
    assert serialized["is_proxy"] is True
    assert serialized["anonymizer_type"] == "TOR Exit Node"
    assert serialized["confidence_score"] == 0.95


def test_email_parser_enriches_vpn_proxy_hop():
    """Verify EmailParser detects Public VPN / Datacenter Proxy in Received headers."""
    raw_email = (
        b"From: invoice@company.example\r\n"
        b"To: finance@victim.example\r\n"
        b"Subject: Overdue Invoice\r\n"
        b"Received: from do-node.cloud.example ([159.65.120.45]) by mx.victim.example with ESMTP id 456; Tue, 01 Jan 2026 10:00:00 +0000\r\n"
        b"\r\n"
        b"Invoice attached."
    )
    result = EmailParser().parse(raw_email)
    assert len(result.trace.hops) == 1
    hop = result.trace.hops[0]
    assert hop.from_ip == "159.65.120.45"
    assert hop.is_tor is False
    assert hop.is_proxy is True
    assert hop.anonymizer_type == "Public VPN / Proxy"
    assert hop.confidence_score == 0.70

    serialized = hop.to_dict()
    assert serialized["is_tor"] is False
    assert serialized["is_proxy"] is True
    assert serialized["anonymizer_type"] == "Public VPN / Proxy"
    assert serialized["confidence_score"] == 0.70

