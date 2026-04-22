from __future__ import annotations

from pathlib import Path

import pytest
from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap


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


def _sip_tcp_segment(
    ts: float,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    raw: bytes,
    seq: int = 1,
):
    """Build a single TCP segment carrying `raw` bytes verbatim.

    Sequence numbers don't affect our parser (it concatenates payloads in
    capture order), so callers can pass any monotonic seq; the argument is
    here just so callers can keep it explicit for readability.
    """
    pkt = (
        Ether(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02")
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=src_port, dport=dst_port, seq=seq, flags="PA")
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


def _sip_bytes(text: str) -> bytes:
    """CRLF-normalize a SIP message template and encode it."""
    return text.replace("\n", "\r\n").encode("utf-8")


@pytest.fixture
def tcp_split_invite_pcap(tmp_path: Path) -> Path:
    """INVITE over TCP with SDP body split across two TCP segments.

    The INVITE arrives in two halves:
      - segment 1: request line + headers up to midway through the SDP body
      - segment 2: remainder of the body + the 200 OK response (separate flow)
    The parser must buffer segment 1, append segment 2, and emit one full
    INVITE as soon as Content-Length bytes have been seen.
    """
    a = "10.0.0.1"
    b = "10.0.0.2"
    ap = 55555
    bp = 5060
    call_id = "call-tcp-split-001@example.com"
    from_hdr = '"Alice" <sip:alice@example.com>;tag=a1'
    to_hdr = '"Bob" <sip:bob@example.com>'
    to_hdr_tagged = to_hdr + ";tag=b2"

    sdp = (
        "v=0\r\n"
        "o=alice 1 1 IN IP4 10.0.0.1\r\n"
        "s=-\r\n"
        "c=IN IP4 10.0.0.1\r\n"
        "t=0 0\r\n"
        "m=audio 49170 RTP/AVP 0\r\n"
    )
    invite = _sip_bytes(
        f"INVITE sip:bob@example.com SIP/2.0\n"
        f"Via: SIP/2.0/TCP 10.0.0.1:55555;branch=z9hG4bK-tcp-split\n"
        f"From: {from_hdr}\n"
        f"To: {to_hdr}\n"
        f"Call-ID: {call_id}\n"
        f"CSeq: 1 INVITE\n"
        f"Content-Type: application/sdp\n"
        f"Content-Length: {len(sdp)}\n"
        f"\n"
    ) + sdp.encode("utf-8")

    # Split the INVITE roughly midway through the SDP body.
    split_at = invite.find(b"s=-") + 3  # somewhere inside the body
    assert 0 < split_at < len(invite), "split point must be inside the INVITE"
    seg_a, seg_b = invite[:split_at], invite[split_at:]

    ok = _sip_bytes(
        f"SIP/2.0 200 OK\n"
        f"Via: SIP/2.0/TCP 10.0.0.1:55555;branch=z9hG4bK-tcp-split\n"
        f"From: {from_hdr}\n"
        f"To: {to_hdr_tagged}\n"
        f"Call-ID: {call_id}\n"
        f"CSeq: 1 INVITE\n"
        f"Content-Length: 0\n\n"
    )

    packets = [
        _sip_tcp_segment(400.000, a, ap, b, bp, seg_a, seq=1),
        _sip_tcp_segment(400.010, a, ap, b, bp, seg_b, seq=1 + len(seg_a)),
        _sip_tcp_segment(400.200, b, bp, a, ap, ok, seq=1),
    ]
    return _write_pcap(tmp_path / "tcp_split_invite.pcap", packets)


@pytest.fixture
def tcp_pipelined_pcap(tmp_path: Path) -> Path:
    """Two back-to-back SIP messages in a single TCP segment.

    Exercises the drain loop: one segment should yield both messages in one
    pass, with no leftover buffer.
    """
    a = "10.0.0.1"
    b = "10.0.0.2"
    ap = 55556
    bp = 5060
    call_id = "call-tcp-pipe-001@example.com"
    alice = '"Alice" <sip:alice@example.com>;tag=a1'
    bob = '"Bob" <sip:bob@example.com>'

    options = _sip_bytes(
        f"OPTIONS sip:bob@example.com SIP/2.0\n"
        f"Via: SIP/2.0/TCP 10.0.0.1:55556;branch=z9hG4bK-opt\n"
        f"From: {alice}\n"
        f"To: {bob}\n"
        f"Call-ID: {call_id}\n"
        f"CSeq: 1 OPTIONS\n"
        f"Content-Length: 0\n\n"
    )
    info = _sip_bytes(
        f"INFO sip:bob@example.com SIP/2.0\n"
        f"Via: SIP/2.0/TCP 10.0.0.1:55556;branch=z9hG4bK-inf\n"
        f"From: {alice}\n"
        f"To: {bob}\n"
        f"Call-ID: {call_id}\n"
        f"CSeq: 2 INFO\n"
        f"Content-Length: 0\n\n"
    )
    packets = [_sip_tcp_segment(500.0, a, ap, b, bp, options + info, seq=1)]
    return _write_pcap(tmp_path / "tcp_pipelined.pcap", packets)


@pytest.fixture
def tcp_truncated_at_eof_pcap(tmp_path: Path) -> Path:
    """TCP stream whose final message is cut off (Content-Length > bytes captured)."""
    a = "10.0.0.1"
    b = "10.0.0.2"
    ap = 55557
    bp = 5060
    call_id = "call-tcp-eof-001@example.com"
    alice = '"Alice" <sip:alice@example.com>;tag=a1'
    bob = '"Bob" <sip:bob@example.com>'

    # Declares Content-Length: 500, delivers only 10 body bytes, then the
    # capture ends — parser should warn and not emit a partial message.
    partial = _sip_bytes(
        f"INVITE sip:bob@example.com SIP/2.0\n"
        f"Via: SIP/2.0/TCP 10.0.0.1:55557;branch=z9hG4bK-eof\n"
        f"From: {alice}\n"
        f"To: {bob}\n"
        f"Call-ID: {call_id}\n"
        f"CSeq: 1 INVITE\n"
        f"Content-Type: application/sdp\n"
        f"Content-Length: 500\n"
        f"\n"
    ) + b"short body"

    packets = [_sip_tcp_segment(600.0, a, ap, b, bp, partial, seq=1)]
    return _write_pcap(tmp_path / "tcp_truncated_eof.pcap", packets)
