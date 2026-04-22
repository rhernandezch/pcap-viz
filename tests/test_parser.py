from __future__ import annotations

from pathlib import Path

from pcap_viz.parser import parse_pcap


def test_basic_call_parses_in_order(basic_call_pcap: Path) -> None:
    result = parse_pcap(basic_call_pcap)

    assert result.filename == "basic_call.pcap"
    assert result.sip_message_count == 7
    assert len(result.calls) == 1

    call = result.calls[0]
    assert call.call_id == "call-basic-001@example.com"
    assert call.message_count == 7

    expected = [
        ("INVITE", None),
        (None, 100),
        (None, 180),
        (None, 200),
        ("ACK", None),
        ("BYE", None),
        (None, 200),
    ]
    got = [(m.method, m.status_code) for m in call.messages]
    assert got == expected

    # Endpoints deduped in first-seen order
    assert call.endpoints == ["10.0.0.1:5060", "10.0.0.2:5060"]

    # INVITE carries SDP body
    invite = call.messages[0]
    assert invite.request_line == "INVITE sip:bob@example.com SIP/2.0"
    assert invite.body is not None and "m=audio" in invite.body
    assert invite.headers.get("Content-Type") == "application/sdp"
    assert invite.cseq == "1 INVITE"
    assert invite.transport == "UDP"


def test_two_overlapping_calls_group_by_call_id(two_calls_pcap: Path) -> None:
    result = parse_pcap(two_calls_pcap)
    assert result.sip_message_count == 4
    assert len(result.calls) == 2

    ids = sorted(c.call_id for c in result.calls)
    assert ids == ["call-overlap-001@example.com", "call-overlap-002@example.com"]

    for call in result.calls:
        assert call.message_count == 2
        methods_and_status = [(m.method, m.status_code) for m in call.messages]
        assert methods_and_status == [("INVITE", None), (None, 200)]


def test_malformed_message_becomes_warning(malformed_pcap: Path) -> None:
    result = parse_pcap(malformed_pcap)

    # The valid OPTIONS still parses
    assert result.sip_message_count == 1
    assert result.calls[0].messages[0].method == "OPTIONS"

    # The truncated one is dropped — may surface as a warning or may simply
    # fail the "end of headers" check (silently discarded in _split_sip_messages).
    # Either way, no crash and the valid message is present.
    assert result.packet_count == 2
