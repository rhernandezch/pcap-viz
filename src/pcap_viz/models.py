from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .sdp import Sdp

Transport = Literal["UDP", "TCP"]


class SipMessage(BaseModel):
    """A single parsed SIP message (request or response)."""

    index: int
    timestamp: float
    src: str
    dst: str
    transport: Transport

    method: str | None = None
    status_code: int | None = None
    status_phrase: str | None = None
    request_line: str | None = None
    status_line: str | None = None

    cseq: str = ""
    call_id: str = ""
    from_uri: str = ""
    to_uri: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    sdp: Sdp | None = None


class Call(BaseModel):
    """All SIP messages that share a Call-ID, in time order."""

    call_id: str
    endpoints: list[str]
    started_at: float
    ended_at: float
    from_uri: str
    to_uri: str
    message_count: int
    messages: list[SipMessage]


class ParseResult(BaseModel):
    """Result of parsing one pcap file."""

    filename: str
    packet_count: int
    sip_message_count: int
    calls: list[Call]
    warnings: list[str] = Field(default_factory=list)
