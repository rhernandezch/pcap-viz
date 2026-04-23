"""Shallow SDP parser.

Lifts the bits of RFC 4566 that matter for debugging AI-voice calls:
per-media kind/port/protocol, payload-type codec names (a=rtpmap), and the
session- or media-level connection address. Anything unrecognized is
silently ignored — the full raw body is still preserved on SipMessage for
anyone who needs the whole thing.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class SdpMedia(BaseModel):
    """One m=/c=/a= block from an SDP body."""

    kind: str  # "audio", "video", "application", ...
    port: int
    proto: str  # "RTP/AVP", "UDP/TLS/RTP/SAVPF", ...
    formats: list[int] = Field(default_factory=list)  # payload types from m=
    rtpmaps: dict[int, str] = Field(default_factory=dict)  # pt -> "PCMU/8000"
    connection_addr: str | None = None  # per-media c= override


class Sdp(BaseModel):
    """A shallow, lossless-enough parse of an SDP body."""

    origin_addr: str | None = None  # IP from o= line
    session_name: str | None = None  # s=
    connection_addr: str | None = None  # session-level c=
    media: list[SdpMedia] = Field(default_factory=list)


def parse_sdp(body: str) -> Sdp | None:
    """Parse an SDP body. Returns None when no recognizable SDP lines exist."""
    sdp = Sdp()
    current: SdpMedia | None = None
    saw_anything = False

    for raw in body.replace("\r\n", "\n").split("\n"):
        line = raw.strip()
        if len(line) < 2 or line[1] != "=":
            continue
        key = line[0]
        value = line[2:].strip()

        if key == "v":
            saw_anything = True
        elif key == "o":
            saw_anything = True
            sdp.origin_addr = _origin_addr(value)
        elif key == "s":
            saw_anything = True
            sdp.session_name = value or None
        elif key == "c":
            saw_anything = True
            addr = _connection_addr(value)
            if current is None:
                sdp.connection_addr = addr
            else:
                current.connection_addr = addr
        elif key == "m":
            saw_anything = True
            media = _parse_m(value)
            if media is not None:
                sdp.media.append(media)
                current = media
        elif key == "a" and current is not None:
            saw_anything = True
            _apply_attribute(current, value)

    return sdp if saw_anything else None


def _origin_addr(value: str) -> str | None:
    # o=<user> <sess-id> <sess-ver> <nettype> <addrtype> <addr>
    parts = value.split()
    return parts[5] if len(parts) >= 6 else None


def _connection_addr(value: str) -> str | None:
    # c=<nettype> <addrtype> <addr>[/ttl][/count]
    parts = value.split()
    if len(parts) < 3:
        return None
    # Strip any "/ttl/count" suffix that can follow the address for multicast.
    return parts[2].split("/", 1)[0]


def _parse_m(value: str) -> SdpMedia | None:
    # m=<media> <port>[/n] <proto> <fmt> <fmt> ...
    parts = value.split()
    if len(parts) < 4:
        return None
    try:
        port = int(parts[1].split("/", 1)[0])
    except ValueError:
        return None
    formats: list[int] = []
    for f in parts[3:]:
        try:
            formats.append(int(f))
        except ValueError:
            # Non-numeric format (valid for some proto variants); skip it
            # rather than fail the whole media block.
            continue
    return SdpMedia(kind=parts[0], port=port, proto=parts[2], formats=formats)


def _apply_attribute(media: SdpMedia, value: str) -> None:
    """Attach a single a= attribute to the current media block."""
    # a=rtpmap:<pt> <encoding name>/<clock rate>[/<channels>]
    if value.startswith("rtpmap:"):
        rest = value[len("rtpmap:") :].strip()
        pt_str, _, codec = rest.partition(" ")
        codec = codec.strip()
        if not codec:
            return
        try:
            pt = int(pt_str)
        except ValueError:
            return
        media.rtpmaps[pt] = codec
