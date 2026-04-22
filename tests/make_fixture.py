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


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/pcap-viz-demo.pcap")
