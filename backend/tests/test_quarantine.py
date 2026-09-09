import os
import sys
import unittest
import pytest

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
parent_dir = os.path.dirname(backend_dir)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from fastapi import HTTPException
from backend.db import init_db, save_case, get_case, list_cases, clear_cases
from backend.main import quarantine_case_endpoint, get_case_by_id


@pytest.mark.anyio
async def test_quarantine_case_success():
    # Setup test case in DB
    test_case = {
        "case_id": "TS-TEST-QUARANTINE-001",
        "status": "ACTIVE",
        "message": {
            "message_id": "<malicious-phish-99@attacker.test>",
            "origin_ip": "198.51.100.88",
            "subject": "Urgent Wire Transfer Request",
        },
        "risk": {
            "score": 95,
            "band": "HIGH",
        },
    }
    save_case(test_case)

    # Call quarantine endpoint
    res = await quarantine_case_endpoint("TS-TEST-QUARANTINE-001")

    assert res is not None
    assert res["status"] == "QUARANTINED"
    assert "mitigation" in res

    mitigation = res["mitigation"]
    assert mitigation["action"] == "IMAP_STORE_FLAGS_DELETED"
    assert mitigation["target_message_id"] == "<malicious-phish-99@attacker.test>"
    assert mitigation["originating_ip_firewall_rule"] == "iptables -A INPUT -s 198.51.100.88 -j DROP"
    assert mitigation["status"] == "APPLIED_SUCCESSFULLY"
    assert "timestamp" in mitigation

    # Verify persistent state in SQLite
    db_case = get_case("TS-TEST-QUARANTINE-001")
    assert db_case is not None
    assert db_case["status"] == "QUARANTINED"
    assert db_case["mitigation"]["action"] == "IMAP_STORE_FLAGS_DELETED"

    # Verify list_cases returns status QUARANTINED
    summaries = list_cases()
    match = next((c for c in summaries if c["case_id"] == "TS-TEST-QUARANTINE-001"), None)
    assert match is not None
    assert match["status"] == "QUARANTINED"


@pytest.mark.anyio
async def test_quarantine_case_fallback_ip_and_message_id():
    test_case = {
        "case_id": "TS-TEST-QUARANTINE-FALLBACK",
        "status": "ACTIVE",
        "message": {
            "subject": "Test Fallback",
        },
        "infrastructure": {
            "indicators": [
                {"type": "domain", "value": "example.com"},
                {"type": "ip", "value": "203.0.113.50"},
            ]
        },
        "risk": {
            "score": 80,
            "band": "HIGH",
        },
    }
    save_case(test_case)

    res = await quarantine_case_endpoint("TS-TEST-QUARANTINE-FALLBACK")
    assert res["status"] == "QUARANTINED"
    assert res["mitigation"]["target_message_id"] == "<TS-TEST-QUARANTINE-FALLBACK@traceshield.internal>"
    assert res["mitigation"]["originating_ip_firewall_rule"] == "iptables -A INPUT -s 203.0.113.50 -j DROP"


@pytest.mark.anyio
async def test_quarantine_case_not_found():
    with pytest.raises(HTTPException) as exc_info:
        await quarantine_case_endpoint("TS-NONEXISTENT-CASE")
    assert exc_info.value.status_code == 404
