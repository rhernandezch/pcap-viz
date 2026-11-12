"""Generate a small SIP pcap for manual/E2E testing.

Run: python tests/make_fixture.py /tmp/basic_call.pcap
"""

from __future__ import annotations

import sys
from pathlib import Path

from scapy.all import IP, UDP, Ether, Raw, wrpcap


def _pkt(ts: float, src_ip: str, src_port: int, dst_ip: str, dst_port: int, text: str):
    raw = text.replace("\n", "\r\n").encode("utf-8")
    pkt = (
        Ether(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02")
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=src_port, dport=dst_port)
        / Raw(load=raw)
    )
    pkt.time = ts
    return pkt


def main(out_path: str) -> None:
    a, b = "10.0.0.1", "10.0.0.2"
    call_id = "call-demo-001@example.com"
    alice = '"Alice" <sip:alice@example.com>;tag=a1'
    bob = '"Bob" <sip:bob@example.com>'
    bob_tagged = bob + ";tag=b2"

    sdp = (
        "v=0\n"
        "o=alice 1 1 IN IP4 10.0.0.1\n"
        "s=-\n"
        "c=IN IP4 10.0.0.1\n"
        "t=0 0\n"
        "m=audio 49170 RTP/AVP 0\n"
    )

    def _invite() -> str:
        body = sdp.replace("\n", "\r\n")
        return (
            f"INVITE sip:bob@example.com SIP/2.0\n"
            f"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-invite\n"
            f"From: {alice}\n"
            f"To: {bob}\n"
            f"Call-ID: {call_id}\n"
            f"CSeq: 1 INVITE\n"
            f"Content-Type: application/sdp\n"
            f"Content-Length: {len(body)}\n"
            f"\n{sdp}"
        )

    def _msg(first_line: str, to_h: str, cseq: str) -> str:
        return (
            f"{first_line}\n"
            f"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-{cseq.split()[0]}\n"
            f"From: {alice}\n"
            f"To: {to_h}\n"
            f"Call-ID: {call_id}\n"
            f"CSeq: {cseq}\n"
            f"Content-Length: 0\n\n"
        )

    pkts = [
        _pkt(1_700_000_000.0, a, 5060, b, 5060, _invite()),
        _pkt(1_700_000_000.05, b, 5060, a, 5060, _msg("SIP/2.0 100 Trying", bob, "1 INVITE")),
        _pkt(1_700_000_000.4, b, 5060, a, 5060, _msg("SIP/2.0 180 Ringing", bob_tagged, "1 INVITE")),
        _pkt(1_700_000_003.1, b, 5060, a, 5060, _msg("SIP/2.0 200 OK", bob_tagged, "1 INVITE")),
        _pkt(1_700_000_003.15, a, 5060, b, 5060, _msg("ACK sip:bob@example.com SIP/2.0", bob_tagged, "1 ACK")),
        _pkt(1_700_000_010.0, b, 5060, a, 5060, _msg("BYE sip:alice@example.com SIP/2.0", alice, "2 BYE")),
        _pkt(1_700_000_010.05, a, 5060, b, 5060, _msg("SIP/2.0 200 OK", alice, "2 BYE")),
    ]

    wrpcap(out_path, pkts)
    print(f"wrote {out_path} ({len(pkts)} packets)")


_SHOWCASE_T0 = 1_700_000_000.0
_UAC, _SBC, _BOT = "10.0.0.1", "10.0.0.10", "10.0.0.20"
_USER_AGENTS = {_UAC: "Zoiper 5.6", _SBC: "Kamailio 5.7", _BOT: "yalo-voice-bot/1.4"}
_SDP = "v=0\no=- 1 1 IN IP4 {ip}\ns=-\nc=IN IP4 {ip}\nt=0 0\nm=audio 49170 RTP/AVP 0 8\n" \
    "a=rtpmap:0 PCMU/8000\na=rtpmap:8 PCMA/8000\n"


def _showcase_msg(
    call_id: str,
    src: str,
    first_line: str,
    cseq: str,
    *,
    sdp: bool = False,
    extra: tuple[str, ...] = (),
) -> str:
    body = _SDP.format(ip=src) if sdp else ""
    branch = f"{call_id.split('@')[0]}-{cseq.replace(' ', '-').lower()}"
    lines = [
        first_line,
        f"Via: SIP/2.0/UDP {src}:5060;branch=z9hG4bK-{branch}",
        'From: "Caller" <sip:caller@showcase.example>;tag=c1',
        "To: <sip:agent@showcase.example>;tag=a1",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq}",
        f"User-Agent: {_USER_AGENTS[src]}",
        *extra,
    ]
    if sdp:
        lines.append("Content-Type: application/sdp")
    # _pkt rewrites each "\n" as "\r\n" on the wire.
    wire_length = len(body) + body.count("\n")
    lines.append(f"Content-Length: {wire_length}")
    return "\n".join(lines) + "\n\n" + body


def _showcase_flows() -> list[tuple[str, float, list[tuple[float, str, str, str, str, dict]]]]:
    invite = "INVITE sip:agent@showcase.example SIP/2.0"
    ack = "ACK sip:agent@showcase.example SIP/2.0"
    bye = "BYE sip:caller@showcase.example SIP/2.0"
    reason = {"extra": ('Reason: Q.850;cause=16;text="Normal call clearing"',)}
    completed = [
        (0.000, _UAC, _SBC, invite, "1 INVITE", {"sdp": True}),
        (0.010, _SBC, _UAC, "SIP/2.0 100 Trying", "1 INVITE", {}),
        (0.020, _SBC, _BOT, invite, "1 INVITE", {"sdp": True}),
        (0.300, _BOT, _SBC, "SIP/2.0 180 Ringing", "1 INVITE", {}),
        (0.310, _SBC, _UAC, "SIP/2.0 180 Ringing", "1 INVITE", {}),
        (1.200, _BOT, _SBC, "SIP/2.0 200 OK", "1 INVITE", {"sdp": True}),
        (1.210, _SBC, _UAC, "SIP/2.0 200 OK", "1 INVITE", {"sdp": True}),
        (1.250, _UAC, _SBC, ack, "1 ACK", {}),
        (1.260, _SBC, _BOT, ack, "1 ACK", {}),
        (30.000, _BOT, _SBC, invite, "2 INVITE", {"sdp": True}),
        (30.010, _SBC, _UAC, invite, "2 INVITE", {"sdp": True}),
        (30.100, _UAC, _SBC, "SIP/2.0 200 OK", "2 INVITE", {"sdp": True}),
        (30.110, _SBC, _BOT, "SIP/2.0 200 OK", "2 INVITE", {"sdp": True}),
        (30.150, _BOT, _SBC, ack, "2 ACK", {}),
        (30.160, _SBC, _UAC, ack, "2 ACK", {}),
        (45.000, _BOT, _SBC, bye, "3 BYE", reason),
        (45.010, _SBC, _UAC, bye, "3 BYE", reason),
        (45.050, _UAC, _SBC, "SIP/2.0 200 OK", "3 BYE", {}),
        (45.060, _SBC, _BOT, "SIP/2.0 200 OK", "3 BYE", {}),
    ]
    rejected = [
        (0.0, _UAC, _SBC, invite, "1 INVITE", {"sdp": True}),
        (0.1, _SBC, _UAC, "SIP/2.0 100 Trying", "1 INVITE", {}),
        (0.5, _SBC, _UAC, "SIP/2.0 486 Busy Here", "1 INVITE", {}),
        (0.55, _UAC, _SBC, ack, "1 ACK", {}),
    ]
    cancelled = [
        (0.0, _UAC, _SBC, invite, "1 INVITE", {"sdp": True}),
        (0.2, _SBC, _UAC, "SIP/2.0 180 Ringing", "1 INVITE", {}),
        (4.0, _UAC, _SBC, "CANCEL sip:agent@showcase.example SIP/2.0", "1 CANCEL", {}),
        (4.05, _SBC, _UAC, "SIP/2.0 200 OK", "1 CANCEL", {}),
        (4.06, _SBC, _UAC, "SIP/2.0 487 Request Terminated", "1 INVITE", {}),
        (4.1, _UAC, _SBC, ack, "1 ACK", {}),
    ]
    unanswered = [
        (0.0, _UAC, _SBC, invite, "1 INVITE", {"sdp": True}),
        (0.1, _SBC, _UAC, "SIP/2.0 100 Trying", "1 INVITE", {}),
    ]
    in_call = [
        (0.0, _UAC, _SBC, invite, "1 INVITE", {"sdp": True}),
        (0.8, _SBC, _UAC, "SIP/2.0 200 OK", "1 INVITE", {"sdp": True}),
        (0.85, _UAC, _SBC, ack, "1 ACK", {}),
    ]
    options = [
        (0.0, _SBC, _BOT, "OPTIONS sip:agent@showcase.example SIP/2.0", "1 OPTIONS", {}),
        (0.02, _BOT, _SBC, "SIP/2.0 200 OK", "1 OPTIONS", {}),
    ]
    redirected = [
        (0.0, _UAC, _SBC, invite, "1 INVITE", {"sdp": True}),
        (0.3, _SBC, _UAC, "SIP/2.0 302 Moved Temporarily", "1 INVITE", {}),
        (0.35, _UAC, _SBC, ack, "1 ACK", {}),
    ]
    flows = [
        ("call-completed@showcase", 0.0, completed),
        ("call-rejected@showcase", 50.0, rejected),
        ("call-cancelled@showcase", 55.0, cancelled),
        ("call-unanswered@showcase", 62.0, unanswered),
        ("call-in-call@showcase", 65.0, in_call),
        ("options-ping@showcase", 70.0, options),
        ("call-redirected@showcase", 72.0, redirected),
    ]
    flows += [(f"keepalive-{i:02d}@showcase", 80.0 + i * 2, options) for i in range(25)]
    return flows


def build_showcase(out_path: Path) -> Path:
    pkts = [
        _pkt(_SHOWCASE_T0 + start + dt, src, 5060, dst, 5060,
             _showcase_msg(call_id, src, first_line, cseq, **opts))
        for call_id, start, flow in _showcase_flows()
        for dt, src, dst, first_line, cseq, opts in flow
    ]
    truncated = _showcase_msg(
        "call-truncated@showcase", _UAC, "INVITE sip:agent@showcase.example SIP/2.0", "1 INVITE"
    ).replace("Content-Length: 0", "Content-Length: 500")
    pkts.append(_pkt(_SHOWCASE_T0 + 140.0, _UAC, 5060, _SBC, 5060, truncated + "short body"))
    pkts.sort(key=lambda p: p.time)
    wrpcap(str(out_path), pkts)
    return out_path


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--showcase"]
    if "--showcase" in sys.argv:
        out = build_showcase(Path(args[0] if args else "/tmp/pcap-viz-showcase.pcap"))
        print(f"wrote {out}")
    else:
        main(args[0] if args else "/tmp/pcap-viz-demo.pcap")
