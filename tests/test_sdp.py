from __future__ import annotations

from pathlib import Path

from pcap_viz.parser import parse_pcap
from pcap_viz.sdp import parse_sdp


def test_parse_sdp_basic_audio() -> None:
    body = (
        "v=0\r\n"
        "o=alice 123 456 IN IP4 10.0.0.1\r\n"
        "s=-\r\n"
        "c=IN IP4 10.0.0.1\r\n"
        "t=0 0\r\n"
        "m=audio 49170 RTP/AVP 0 8 101\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=rtpmap:8 PCMA/8000\r\n"
        "a=rtpmap:101 telephone-event/8000\r\n"
    )
    sdp = parse_sdp(body)
    assert sdp is not None
    assert sdp.origin_addr == "10.0.0.1"
    assert sdp.connection_addr == "10.0.0.1"
    assert sdp.session_name == "-"
    assert len(sdp.media) == 1

    audio = sdp.media[0]
    assert audio.kind == "audio"
    assert audio.port == 49170
    assert audio.proto == "RTP/AVP"
    assert audio.formats == [0, 8, 101]
    assert audio.rtpmaps == {
        0: "PCMU/8000",
        8: "PCMA/8000",
        101: "telephone-event/8000",
    }
    assert audio.connection_addr is None  # falls back to session-level


def test_parse_sdp_per_media_connection_overrides_session() -> None:
    body = (
        "v=0\r\n"
        "c=IN IP4 10.0.0.1\r\n"
        "m=audio 49170 RTP/AVP 0\r\n"
        "c=IN IP4 192.0.2.5\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
    )
    sdp = parse_sdp(body)
    assert sdp is not None
    assert sdp.connection_addr == "10.0.0.1"
    assert sdp.media[0].connection_addr == "192.0.2.5"


def test_parse_sdp_ignores_unknown_and_malformed_lines() -> None:
    body = (
        "v=0\r\n"
        "o=- 0 0 IN IP4 10.0.0.1\r\n"
        "m=audio 49170 RTP/AVP 0\r\n"
        "garbage without equals\r\n"
        "a=rtpmap:not-a-number PCMU/8000\r\n"  # PT not numeric — skipped
        "a=rtpmap:0 PCMU/8000\r\n"             # valid
        "a=fmtp:0 something\r\n"               # non-rtpmap attribute — ignored
    )
    sdp = parse_sdp(body)
    assert sdp is not None
    assert sdp.media[0].rtpmaps == {0: "PCMU/8000"}


def test_parse_sdp_multiple_media_streams() -> None:
    body = (
        "v=0\r\n"
        "o=- 0 0 IN IP4 10.0.0.1\r\n"
        "c=IN IP4 10.0.0.1\r\n"
        "m=audio 49170 RTP/AVP 0\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "m=video 51234 RTP/AVP 96\r\n"
        "a=rtpmap:96 H264/90000\r\n"
    )
    sdp = parse_sdp(body)
    assert sdp is not None
    kinds = [m.kind for m in sdp.media]
    assert kinds == ["audio", "video"]
    assert sdp.media[0].rtpmaps == {0: "PCMU/8000"}
    assert sdp.media[1].rtpmaps == {96: "H264/90000"}


def test_parse_sdp_returns_none_for_non_sdp_body() -> None:
    assert parse_sdp("") is None
    assert parse_sdp("plain text with no sdp lines") is None


def test_parse_pcap_attaches_sdp_to_invite(basic_call_pcap: Path) -> None:
    """The basic-call fixture's INVITE carries an SDP body; it should now parse."""
    result = parse_pcap(basic_call_pcap)
    invite = result.calls[0].messages[0]
    assert invite.method == "INVITE"
    assert invite.sdp is not None
    assert invite.sdp.connection_addr == "10.0.0.1"
    assert len(invite.sdp.media) == 1
    assert invite.sdp.media[0].kind == "audio"
    assert invite.sdp.media[0].port == 49170
    assert invite.sdp.media[0].formats == [0]


def test_parse_pcap_leaves_sdp_none_on_non_sdp_bodies(basic_call_pcap: Path) -> None:
    """Messages without application/sdp bodies must not get an SDP attached."""
    result = parse_pcap(basic_call_pcap)
    for msg in result.calls[0].messages[1:]:  # everything after the INVITE
        assert msg.sdp is None, f"{msg.method or msg.status_code} should not have SDP"
