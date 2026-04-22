from __future__ import annotations

from pathlib import Path

import pytest
from scapy.all import IP, UDP, Ether, Raw, wrpcap


def _sip_udp_packet(
    ts: float,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    text: str,
):
    raw = text.replace("\n", "\r\n").encode("utf-8")
    pkt = (
        Ether(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02")
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=src_port, dport=dst_port)
        / Raw(load=raw)
    )
    pkt.time = ts
    return pkt


def _write_pcap(path: Path, packets) -> Path:
    wrpcap(str(path), packets)
    return path


@pytest.fixture
def basic_call_pcap(tmp_path: Path) -> Path:
    """One complete SIP call: INVITE -> 100 -> 180 -> 200 -> ACK -> BYE -> 200."""
    a = "10.0.0.1"
    b = "10.0.0.2"
    ap = 5060
    bp = 5060
    call_id = "call-basic-001@example.com"
    from_hdr = '"Alice" <sip:alice@example.com>;tag=a1'
    to_hdr = '"Bob" <sip:bob@example.com>'
    to_hdr_tagged = to_hdr + ";tag=b2"

    sdp = (
        "v=0\n"
        "o=alice 1 1 IN IP4 10.0.0.1\n"
        "s=-\n"
        "c=IN IP4 10.0.0.1\n"
        "t=0 0\n"
        "m=audio 49170 RTP/AVP 0\n"
    )

    invite = (
        f"INVITE sip:bob@example.com SIP/2.0\n"
        f"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-invite\n"
        f"From: {from_hdr}\n"
        f"To: {to_hdr}\n"
        f"Call-ID: {call_id}\n"
        f"CSeq: 1 INVITE\n"
        f"Content-Type: application/sdp\n"
        f"Content-Length: {len(sdp.replace(chr(10), chr(13) + chr(10)))}\n"
        f"\n{sdp}"
    )
    trying = (
        f"SIP/2.0 100 Trying\n"
        f"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-invite\n"
        f"From: {from_hdr}\n"
        f"To: {to_hdr}\n"
        f"Call-ID: {call_id}\n"
        f"CSeq: 1 INVITE\n"
        f"Content-Length: 0\n\n"
    )
    ringing = (
        f"SIP/2.0 180 Ringing\n"
        f"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-invite\n"
        f"From: {from_hdr}\n"
        f"To: {to_hdr_tagged}\n"
        f"Call-ID: {call_id}\n"
        f"CSeq: 1 INVITE\n"
        f"Content-Length: 0\n\n"
    )
    ok = (
        f"SIP/2.0 200 OK\n"
        f"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-invite\n"
        f"From: {from_hdr}\n"
        f"To: {to_hdr_tagged}\n"
        f"Call-ID: {call_id}\n"
        f"CSeq: 1 INVITE\n"
        f"Content-Length: 0\n\n"
    )
    ack = (
        f"ACK sip:bob@example.com SIP/2.0\n"
        f"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-ack\n"
        f"From: {from_hdr}\n"
        f"To: {to_hdr_tagged}\n"
        f"Call-ID: {call_id}\n"
        f"CSeq: 1 ACK\n"
        f"Content-Length: 0\n\n"
    )
    bye = (
        f"BYE sip:alice@example.com SIP/2.0\n"
        f"Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-bye\n"
        f"From: {to_hdr_tagged}\n"
        f"To: {from_hdr}\n"
        f"Call-ID: {call_id}\n"
        f"CSeq: 2 BYE\n"
        f"Content-Length: 0\n\n"
    )
    bye_ok = (
        f"SIP/2.0 200 OK\n"
        f"Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-bye\n"
        f"From: {to_hdr_tagged}\n"
        f"To: {from_hdr}\n"
        f"Call-ID: {call_id}\n"
        f"CSeq: 2 BYE\n"
        f"Content-Length: 0\n\n"
    )

    packets = [
        _sip_udp_packet(1_000_000.0, a, ap, b, bp, invite),
        _sip_udp_packet(1_000_000.05, b, bp, a, ap, trying),
        _sip_udp_packet(1_000_000.1, b, bp, a, ap, ringing),
        _sip_udp_packet(1_000_003.0, b, bp, a, ap, ok),
        _sip_udp_packet(1_000_003.05, a, ap, b, bp, ack),
        _sip_udp_packet(1_000_010.0, b, bp, a, ap, bye),
        _sip_udp_packet(1_000_010.05, a, ap, b, bp, bye_ok),
    ]
    return _write_pcap(tmp_path / "basic_call.pcap", packets)


@pytest.fixture
def two_calls_pcap(tmp_path: Path) -> Path:
    """Two overlapping calls, interleaved in time."""
    a = "10.0.0.1"
    b = "10.0.0.2"
    c = "10.0.0.3"

    def msg(call_id: str, first_line: str, from_h: str, to_h: str, cseq: str) -> str:
        return (
            f"{first_line}\n"
            f"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-{call_id[:6]}\n"
            f"From: {from_h}\n"
            f"To: {to_h}\n"
            f"Call-ID: {call_id}\n"
            f"CSeq: {cseq}\n"
            f"Content-Length: 0\n\n"
        )

    alice = '"Alice" <sip:alice@example.com>;tag=a1'
    bob = '"Bob" <sip:bob@example.com>'
    carol = '"Carol" <sip:carol@example.com>'

    call1 = "call-overlap-001@example.com"
    call2 = "call-overlap-002@example.com"

    packets = [
        _sip_udp_packet(
            100.0, a, 5060, b, 5060,
            msg(call1, "INVITE sip:bob@example.com SIP/2.0", alice, bob, "1 INVITE"),
        ),
        _sip_udp_packet(
            100.1, a, 5060, c, 5060,
            msg(call2, "INVITE sip:carol@example.com SIP/2.0", alice, carol, "1 INVITE"),
        ),
        _sip_udp_packet(
            100.2, b, 5060, a, 5060,
            msg(call1, "SIP/2.0 200 OK", alice, bob + ";tag=b2", "1 INVITE"),
        ),
        _sip_udp_packet(
            100.3, c, 5060, a, 5060,
            msg(call2, "SIP/2.0 200 OK", alice, carol + ";tag=c2", "1 INVITE"),
        ),
    ]
    return _write_pcap(tmp_path / "two_calls.pcap", packets)


@pytest.fixture
def truncated_body_pcap(tmp_path: Path) -> Path:
    """One SIP message whose Content-Length exceeds the captured body."""
    a = "10.0.0.1"
    b = "10.0.0.2"
    call_id = "call-trunc-001@example.com"
    alice = '"Alice" <sip:alice@example.com>;tag=a1'
    bob = '"Bob" <sip:bob@example.com>'

    # Content-Length claims 500 bytes of body, but only "short body" (10) is present.
    truncated = (
        f"INVITE sip:bob@example.com SIP/2.0\n"
        f"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-trunc\n"
        f"From: {alice}\n"
        f"To: {bob}\n"
        f"Call-ID: {call_id}\n"
        f"CSeq: 1 INVITE\n"
        f"Content-Type: application/sdp\n"
        f"Content-Length: 500\n"
        f"\nshort body"
    )

    packets = [_sip_udp_packet(300.0, a, 5060, b, 5060, truncated)]
    return _write_pcap(tmp_path / "truncated_body.pcap", packets)


@pytest.fixture
def malformed_pcap(tmp_path: Path) -> Path:
    """One valid SIP message plus one that's truncated (no end-of-headers)."""
    a = "10.0.0.1"
    b = "10.0.0.2"
    call_id = "call-mal-001@example.com"
    alice = '"Alice" <sip:alice@example.com>;tag=a1'
    bob = '"Bob" <sip:bob@example.com>'

    valid = (
        f"OPTIONS sip:bob@example.com SIP/2.0\n"
        f"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-opt\n"
        f"From: {alice}\n"
        f"To: {bob}\n"
        f"Call-ID: {call_id}\n"
        f"CSeq: 1 OPTIONS\n"
        f"Content-Length: 0\n\n"
    )
    # Looks like SIP (starts with INVITE) but never terminates headers
    truncated = "INVITE sip:bob@example.com SIP/2.0\nVia: SIP/2.0/UDP 10.0.0.1:5060"

    packets = [
        _sip_udp_packet(200.0, a, 5060, b, 5060, valid),
        _sip_udp_packet(200.1, a, 5060, b, 5060, truncated),
    ]
    return _write_pcap(tmp_path / "malformed.pcap", packets)
