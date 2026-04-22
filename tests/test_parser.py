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


def test_truncated_body_emits_warning_and_no_message(truncated_body_pcap: Path) -> None:
    result = parse_pcap(truncated_body_pcap)

    # The incomplete message is NOT surfaced as a parsed SIP message.
    assert result.sip_message_count == 0
    assert result.calls == []

    # It IS surfaced as a warning, so truncated captures are visible to the user.
    assert any("truncated SIP" in w for w in result.warnings)


def test_malformed_message_becomes_warning(malformed_pcap: Path) -> None:
    result = parse_pcap(malformed_pcap)

    # The valid OPTIONS still parses
    assert result.sip_message_count == 1
    assert result.calls[0].messages[0].method == "OPTIONS"

    # The truncated one is dropped — may surface as a warning or may simply
    # fail the "end of headers" check (silently discarded in _split_sip_messages).
    # Either way, no crash and the valid message is present.
    assert result.packet_count == 2


def test_tcp_reassembles_invite_split_across_segments(
    tcp_split_invite_pcap: Path,
) -> None:
    """An INVITE whose body spans two TCP segments must reassemble into one message."""
    result = parse_pcap(tcp_split_invite_pcap)

    assert result.warnings == []
    assert result.sip_message_count == 2
    assert len(result.calls) == 1

    call = result.calls[0]
    assert call.call_id == "call-tcp-split-001@example.com"
    assert [(m.method, m.status_code) for m in call.messages] == [
        ("INVITE", None),
        (None, 200),
    ]
    invite = call.messages[0]
    assert invite.transport == "TCP"
    # The full SDP must be present, proving both segments contributed to the body.
    assert invite.body is not None
    assert "m=audio 49170" in invite.body


def test_tcp_pipelined_segment_yields_both_messages(
    tcp_pipelined_pcap: Path,
) -> None:
    """A single TCP segment with two back-to-back SIP messages emits both."""
    result = parse_pcap(tcp_pipelined_pcap)

    assert result.warnings == []
    assert result.sip_message_count == 2
    methods = [m.method for m in result.calls[0].messages]
    assert methods == ["OPTIONS", "INFO"]
    assert all(m.transport == "TCP" for m in result.calls[0].messages)


def test_tcp_truncated_at_eof_warns_and_drops_partial(
    tcp_truncated_at_eof_pcap: Path,
) -> None:
    """A TCP stream ending mid-body surfaces a warning; no partial SipMessage."""
    result = parse_pcap(tcp_truncated_at_eof_pcap)

    assert result.sip_message_count == 0
    assert result.calls == []
    assert any(
        "TCP flow" in w and "truncated SIP" in w for w in result.warnings
    ), result.warnings
