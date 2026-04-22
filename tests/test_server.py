from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pcap_viz.parser import parse_pcap
from pcap_viz.server import create_app


def test_parse_and_fetch_session(basic_call_pcap: Path) -> None:
    app = create_app()
    client = TestClient(app)

    with basic_call_pcap.open("rb") as fh:
        resp = client.post(
            "/api/parse",
            files={"file": ("basic_call.pcap", fh, "application/vnd.tcpdump.pcap")},
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    session_id = body["session_id"]
    assert len(body["result"]["calls"]) == 1
    assert body["result"]["sip_message_count"] == 7
    assert body["result"]["filename"] == "basic_call.pcap"

    resp2 = client.get(f"/api/session/{session_id}")
    assert resp2.status_code == 200
    assert resp2.json()["sip_message_count"] == 7

    missing = client.get("/api/session/nope")
    assert missing.status_code == 404


def test_preload_endpoint_advertises_preloaded_session(basic_call_pcap: Path) -> None:
    preloaded = parse_pcap(basic_call_pcap)
    app = create_app(preload=preloaded)
    client = TestClient(app)

    pre = client.get("/api/preload").json()
    assert pre["session_id"] is not None

    got = client.get(f"/api/session/{pre['session_id']}")
    assert got.status_code == 200
    assert got.json()["sip_message_count"] == 7


def test_empty_preload() -> None:
    app = create_app()
    client = TestClient(app)
    assert client.get("/api/preload").json() == {"session_id": None}
    assert client.get("/api/health").json() == {"status": "ok"}


def test_oversize_upload_rejected_with_413(monkeypatch: pytest.MonkeyPatch) -> None:
    # Drop the cap to 4 KB and send 8 KB so the test stays fast and low-memory.
    monkeypatch.setattr("pcap_viz.server.MAX_UPLOAD_BYTES", 4 * 1024)
    monkeypatch.setattr("pcap_viz.server.UPLOAD_CHUNK_BYTES", 1024)

    app = create_app()
    client = TestClient(app)

    payload = b"\x00" * (8 * 1024)
    resp = client.post(
        "/api/parse",
        files={"file": ("big.pcap", payload, "application/vnd.tcpdump.pcap")},
    )
    assert resp.status_code == 413
    assert "too large" in resp.json()["detail"]
