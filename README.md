# pcap-viz

Local SIP signaling **ladder-diagram viewer** for debugging AI voice calls.

Drop a `.pcap` / `.pcapng` on the browser (or pass it on the CLI) and see one
ladder per Call-ID: endpoint lanes on the X axis, time on Y, arrows for each
SIP message with method/status labels, and a click-to-inspect panel showing
full headers and SDP body.

Pure Python backend (no tshark/Wireshark required), React + Vite frontend.

## Scope (v1)

- SIP over UDP/TCP signaling only (INVITE / 1xx-6xx / ACK / BYE / CANCEL / re-INVITE / OPTIONS)
- Grouped by `Call-ID`
- Click a message to see all headers + body
- Drag-and-drop additional PCAPs into an open session (stacked as tabs)

**Out of scope for v1:** audio playback, jitter/loss stats, DTMF, WebRTC ICE/DTLS/SRTP
on the ladder, SRTP decryption via keylog.

## Install & run

```bash
# Backend
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Frontend (one-time build → served by the backend)
cd frontend
npm install
npm run build
cd ..

# Launch with a PCAP
pcap-viz ./path/to/call.pcap

# Or launch empty and drop files in
pcap-viz
```

## Development

Run the backend and Vite dev server separately for hot-reload:

```bash
# Terminal 1 — backend on :8765
uvicorn pcap_viz.server:app --reload --port 8765

# Terminal 2 — Vite on :5173, proxies /api to :8765
cd frontend && npm run dev
```

## Configuration

The server reads these environment variables at startup (defaults in parens):

| Variable                  | Purpose                                   | Default |
| ------------------------- | ----------------------------------------- | ------- |
| `PCAP_VIZ_MAX_UPLOAD_MB`  | `/api/parse` size cap, in megabytes       | `100`   |
| `PCAP_VIZ_MAX_SESSIONS`   | Bounded LRU capacity for parsed sessions  | `32`    |

Example: `PCAP_VIZ_MAX_UPLOAD_MB=500 pcap-viz`.

## Tests

```bash
pytest
```
