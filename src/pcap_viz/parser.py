from __future__ import annotations

import socket
from dataclasses import dataclass, field
from pathlib import Path

import dpkt

from .models import Call, ParseResult, SipMessage, Transport
from .sdp import parse_sdp

SIP_METHODS = frozenset(
    {
        "INVITE",
        "ACK",
        "BYE",
        "CANCEL",
        "OPTIONS",
        "REGISTER",
        "PRACK",
        "SUBSCRIBE",
        "NOTIFY",
        "PUBLISH",
        "INFO",
        "REFER",
        "MESSAGE",
        "UPDATE",
    }
)

DLT_EN10MB = 1
DLT_RAW = 12
DLT_LINUX_SLL = 113

PCAPNG_MAGIC = b"\n\r\r\n"


@dataclass
class _TcpFlow:
    """Per-direction TCP reassembly state for a SIP-over-TCP byte stream."""

    src: str
    dst: str
    buffer: bytes = b""
    last_ts: float = 0.0
    # True once we've confirmed the first bytes of the stream look like SIP,
    # so we keep appending without re-checking every segment.
    confirmed: bool = False
    warnings: list[str] = field(default_factory=list)


def parse_pcap(path: str | Path) -> ParseResult:
    """Parse a pcap/pcapng file and return structured SIP ladder data."""
    path = Path(path)
    messages: list[SipMessage] = []
    warnings: list[str] = []
    tcp_flows: dict[tuple[str, str], _TcpFlow] = {}
    packet_count = 0
    index = 0

    with path.open("rb") as f:
        head = f.read(4)
        f.seek(0)
        reader = dpkt.pcapng.Reader(f) if head == PCAPNG_MAGIC else dpkt.pcap.Reader(f)
        linktype = reader.datalink()

        for ts, buf in reader:
            packet_count += 1
            extracted = _extract_l4(buf, linktype)
            if extracted is None:
                continue
            payload, transport, src, sport, dst, dport = extracted
            if not payload:
                continue

            src_addr = _fmt_endpoint(src, sport)
            dst_addr = _fmt_endpoint(dst, dport)

            if transport == "UDP":
                if not _looks_like_sip(payload):
                    continue
                raw_messages, truncated = _split_sip_messages(payload)
                if truncated:
                    warnings.append(
                        f"packet #{packet_count}: truncated SIP "
                        "(Content-Length exceeds captured payload)"
                    )
                for raw in raw_messages:
                    index = _emit_message(
                        raw,
                        index=index,
                        timestamp=ts,
                        src=src_addr,
                        dst=dst_addr,
                        transport="UDP",
                        messages=messages,
                        warnings=warnings,
                        context=f"packet #{packet_count}",
                    )
            else:  # TCP
                index = _feed_tcp_segment(
                    flows=tcp_flows,
                    src_addr=src_addr,
                    dst_addr=dst_addr,
                    payload=payload,
                    ts=ts,
                    index=index,
                    messages=messages,
                    warnings=warnings,
                )

    # Any TCP flow that still has buffered bytes at end-of-capture means a
    # partial SIP message we never got to finish — surface it as a warning.
    for flow in tcp_flows.values():
        if flow.buffer:
            warnings.append(
                f"TCP flow {flow.src} -> {flow.dst}: truncated SIP "
                "(incomplete data at end of capture)"
            )

    return ParseResult(
        filename=path.name,
        packet_count=packet_count,
        sip_message_count=len(messages),
        calls=_group_by_call_id(messages),
        warnings=warnings,
    )


def _emit_message(
    raw: bytes,
    *,
    index: int,
    timestamp: float,
    src: str,
    dst: str,
    transport: Transport,
    messages: list[SipMessage],
    warnings: list[str],
    context: str,
) -> int:
    """Parse one raw SIP message and append it to `messages`; returns new index."""
    try:
        msg = _parse_one_message(
            raw,
            index=index,
            timestamp=timestamp,
            src=src,
            dst=dst,
            transport=transport,
        )
    except Exception as exc:
        warnings.append(f"{context}: malformed SIP: {exc}")
        return index
    messages.append(msg)
    return index + 1


def _feed_tcp_segment(
    *,
    flows: dict[tuple[str, str], _TcpFlow],
    src_addr: str,
    dst_addr: str,
    payload: bytes,
    ts: float,
    index: int,
    messages: list[SipMessage],
    warnings: list[str],
) -> int:
    """Accumulate a TCP segment into its flow and drain any complete messages."""
    key = (src_addr, dst_addr)
    flow = flows.get(key)
    if flow is None:
        # Only start tracking a flow once its first bytes look like SIP;
        # otherwise we'd buffer every non-SIP TCP conversation in the capture.
        if not _looks_like_sip(payload):
            return index
        flow = _TcpFlow(src=src_addr, dst=dst_addr, confirmed=True)
        flows[key] = flow

    flow.buffer += payload
    flow.last_ts = ts

    raw_messages, flow.buffer = _drain_sip_buffer(flow.buffer)
    for raw in raw_messages:
        index = _emit_message(
            raw,
            index=index,
            timestamp=flow.last_ts,
            src=src_addr,
            dst=dst_addr,
            transport="TCP",
            messages=messages,
            warnings=warnings,
            context=f"TCP flow {src_addr} -> {dst_addr}",
        )
    return index


def _fmt_endpoint(addr: str, port: int) -> str:
    if ":" in addr:
        return f"[{addr}]:{port}"
    return f"{addr}:{port}"


def _extract_l4(
    buf: bytes, linktype: int
) -> tuple[bytes, Transport, str, int, str, int] | None:
    """Decode L2/L3/L4 and return (payload, transport, src, sport, dst, dport) or None."""
    try:
        if linktype == DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
        elif linktype == DLT_LINUX_SLL:
            sll = dpkt.sll.SLL(buf)
            ip = sll.data
        elif linktype == DLT_RAW:
            version = buf[0] >> 4 if buf else 0
            if version == 4:
                ip = dpkt.ip.IP(buf)
            elif version == 6:
                ip = dpkt.ip6.IP6(buf)
            else:
                return None
        else:
            return None
    except dpkt.dpkt.UnpackError:
        return None

    if isinstance(ip, dpkt.ip.IP):
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)
    elif isinstance(ip, dpkt.ip6.IP6):
        src = socket.inet_ntop(socket.AF_INET6, ip.src)
        dst = socket.inet_ntop(socket.AF_INET6, ip.dst)
    else:
        return None

    l4 = ip.data
    if isinstance(l4, dpkt.udp.UDP):
        return bytes(l4.data), "UDP", src, l4.sport, dst, l4.dport
    if isinstance(l4, dpkt.tcp.TCP):
        return bytes(l4.data), "TCP", src, l4.sport, dst, l4.dport
    return None


def _looks_like_sip(payload: bytes) -> bool:
    if payload.startswith(b"SIP/2.0 "):
        return True
    space = payload.find(b" ")
    if space < 1:
        return False
    token = payload[:space].decode("ascii", errors="ignore")
    return token in SIP_METHODS


def _drain_sip_buffer(buf: bytes) -> tuple[list[bytes], bytes]:
    """Extract complete SIP messages from `buf`; return leftover bytes.

    Leftover is whatever remains after the last complete message:
      - empty if the buffer ended on a message boundary
      - incomplete headers (no CRLF-CRLF yet), or a complete header whose body
        is shorter than Content-Length, otherwise

    Callers decide whether leftover means "wait for more" (TCP reassembly) or
    "truncated" (UDP datagram, where the buffer is self-contained).
    """
    messages: list[bytes] = []
    while buf:
        header_end = buf.find(b"\r\n\r\n")
        if header_end < 0:
            return messages, buf
        content_length = _extract_content_length(buf[:header_end])
        message_end = header_end + 4 + content_length
        if message_end > len(buf):
            return messages, buf
        messages.append(buf[:message_end])
        buf = buf[message_end:].lstrip(b"\r\n")
    return messages, b""


def _split_sip_messages(payload: bytes) -> tuple[list[bytes], bool]:
    """Split a self-contained UDP datagram into (messages, truncated).

    Truncation only applies when a message's Content-Length ran past the
    datagram — leftover without even a full header block is just trailing
    junk and is silently dropped to match pre-TCP behavior.
    """
    messages, leftover = _drain_sip_buffer(payload)
    truncated = b"\r\n\r\n" in leftover
    return messages, truncated


def _extract_content_length(header_block: bytes) -> int:
    for line in header_block.split(b"\r\n")[1:]:
        if b":" not in line:
            continue
        name, _, value = line.partition(b":")
        name_low = name.strip().lower()
        if name_low in (b"content-length", b"l"):
            try:
                return int(value.strip())
            except ValueError:
                return 0
    return 0


def _parse_one_message(
    raw: bytes,
    *,
    index: int,
    timestamp: float,
    src: str,
    dst: str,
    transport: Transport,
) -> SipMessage:
    header_end = raw.find(b"\r\n\r\n")
    if header_end < 0:
        raise ValueError("no end-of-headers")

    header_text = raw[:header_end].decode("utf-8", errors="replace")
    body_bytes = raw[header_end + 4 :]
    body = body_bytes.decode("utf-8", errors="replace") if body_bytes else None

    lines = header_text.split("\r\n")
    first_line = lines[0]

    method: str | None = None
    status_code: int | None = None
    status_phrase: str | None = None
    request_line: str | None = None
    status_line: str | None = None

    if first_line.startswith("SIP/2.0 "):
        status_line = first_line
        parts = first_line.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])
        if len(parts) >= 3:
            status_phrase = parts[2]
    else:
        request_line = first_line
        parts = first_line.split(" ", 2)
        if parts:
            method = parts[0]

    headers: dict[str, str] = {}
    current_name: str | None = None
    for line in lines[1:]:
        if not line:
            continue
        if line[:1] in (" ", "\t") and current_name is not None:
            headers[current_name] = headers[current_name] + " " + line.strip()
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip()
        value = value.strip()
        if name in headers:
            headers[name] = headers[name] + ", " + value
        else:
            headers[name] = value
        current_name = name

    content_type = _header_ci(headers, "Content-Type", "c")
    sdp = (
        parse_sdp(body)
        if body and content_type.lower().split(";", 1)[0].strip() == "application/sdp"
        else None
    )

    return SipMessage(
        index=index,
        timestamp=timestamp,
        src=src,
        dst=dst,
        transport=transport,
        method=method,
        status_code=status_code,
        status_phrase=status_phrase,
        request_line=request_line,
        status_line=status_line,
        cseq=_header_ci(headers, "CSeq"),
        call_id=_header_ci(headers, "Call-ID", "i"),
        from_uri=_header_ci(headers, "From", "f"),
        to_uri=_header_ci(headers, "To", "t"),
        headers=headers,
        body=body,
        sdp=sdp,
    )


def _header_ci(headers: dict[str, str], *names: str) -> str:
    lowered = {k.lower(): v for k, v in headers.items()}
    for n in names:
        value = lowered.get(n.lower())
        if value is not None:
            return value
    return ""


def _group_by_call_id(messages: list[SipMessage]) -> list[Call]:
    buckets: dict[str, list[SipMessage]] = {}
    for m in messages:
        if not m.call_id:
            continue
        buckets.setdefault(m.call_id, []).append(m)

    calls: list[Call] = []
    for call_id, msgs in buckets.items():
        msgs.sort(key=lambda m: (m.timestamp, m.index))
        endpoints: list[str] = []
        seen: set[str] = set()
        for m in msgs:
            for ep in (m.src, m.dst):
                if ep not in seen:
                    seen.add(ep)
                    endpoints.append(ep)
        calls.append(
            Call(
                call_id=call_id,
                endpoints=endpoints,
                started_at=msgs[0].timestamp,
                ended_at=msgs[-1].timestamp,
                from_uri=msgs[0].from_uri,
                to_uri=msgs[0].to_uri,
                message_count=len(msgs),
                messages=msgs,
            )
        )

    calls.sort(key=lambda c: c.started_at)
    return calls
