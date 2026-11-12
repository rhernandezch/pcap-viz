export type Transport = "UDP" | "TCP";

export interface SdpMedia {
  kind: string;
  port: number;
  proto: string;
  formats: number[];
  rtpmaps: Record<string, string>;
  connection_addr: string | null;
}

export interface Sdp {
  origin_addr: string | null;
  session_name: string | null;
  connection_addr: string | null;
  media: SdpMedia[];
}

export interface SipMessage {
  index: number;
  timestamp: number;
  src: string;
  dst: string;
  transport: Transport;
  method: string | null;
  status_code: number | null;
  status_phrase: string | null;
  request_line: string | null;
  status_line: string | null;
  cseq: string;
  call_id: string;
  from_uri: string;
  to_uri: string;
  headers: Record<string, string>;
  body: string | null;
  sdp: Sdp | null;
}

export interface Call {
  call_id: string;
  endpoints: string[];
  started_at: number;
  ended_at: number;
  from_uri: string;
  to_uri: string;
  message_count: number;
  messages: SipMessage[];
}

export interface ParseResult {
  filename: string;
  packet_count: number;
  sip_message_count: number;
  calls: Call[];
  warnings: string[];
}

export interface ParseResponse {
  session_id: string;
  result: ParseResult;
}
