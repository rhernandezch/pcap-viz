from __future__ import annotations

import logging
import tempfile
import uuid
from collections import OrderedDict
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .models import ParseResult
from .parser import parse_pcap

logger = logging.getLogger(__name__)

MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MB
MAX_SESSIONS = 32
UPLOAD_CHUNK_BYTES = 1024 * 1024  # 1 MB

STATIC_DIR = Path(__file__).parent / "static"


class SessionStore:
    """Bounded in-memory LRU for parsed sessions."""

    def __init__(self, max_items: int = MAX_SESSIONS) -> None:
        self._items: OrderedDict[str, ParseResult] = OrderedDict()
        self._max = max_items

    def put(self, result: ParseResult) -> str:
        session_id = uuid.uuid4().hex
        self._items[session_id] = result
        self._items.move_to_end(session_id)
        while len(self._items) > self._max:
            self._items.popitem(last=False)
        return session_id

    def get(self, session_id: str) -> ParseResult | None:
        result = self._items.get(session_id)
        if result is not None:
            self._items.move_to_end(session_id)
        return result


class ParseResponse(BaseModel):
    session_id: str
    result: ParseResult


def create_app(preload: ParseResult | None = None) -> FastAPI:
    app = FastAPI(title="pcap-viz", version="0.1.0")
    store = SessionStore()
    preload_id: str | None = store.put(preload) if preload is not None else None

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/preload")
    def preload_session() -> dict[str, str | None]:
        """Return the session_id the CLI pre-parsed, if any."""
        return {"session_id": preload_id}

    @app.post("/api/parse", response_model=ParseResponse)
    async def parse(file: UploadFile = File(...)) -> ParseResponse:
        suffix = ".pcapng" if (file.filename or "").endswith(".pcapng") else ".pcap"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as tmp:
            total = 0
            while True:
                chunk = await file.read(UPLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"pcap too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)",
                    )
                tmp.write(chunk)
            tmp.flush()
            try:
                result = parse_pcap(tmp.name)
            except Exception:
                # Log the traceback server-side; the client gets a generic
                # message so we don't leak stack traces or file paths.
                logger.exception(
                    "failed to parse pcap upload (filename=%r)", file.filename
                )
                raise HTTPException(status_code=400, detail="failed to parse pcap")
        result.filename = file.filename or result.filename
        session_id = store.put(result)
        return ParseResponse(session_id=session_id, result=result)

    @app.get("/api/session/{session_id}", response_model=ParseResult)
    def get_session(session_id: str) -> ParseResult:
        result = store.get(session_id)
        if result is None:
            raise HTTPException(status_code=404, detail="session not found")
        return result

    _mount_frontend(app)
    return app


def _mount_frontend(app: FastAPI) -> None:
    """Serve the built React frontend from src/pcap_viz/static/ if present."""
    if not STATIC_DIR.exists():
        @app.get("/")
        def frontend_missing() -> dict[str, str]:
            return {
                "error": "frontend not built",
                "hint": "cd frontend && npm install && npm run build",
            }
        return

    assets = STATIC_DIR / "assets"
    if assets.exists():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    index_path = STATIC_DIR / "index.html"

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(index_path)

    @app.get("/{path:path}")
    def spa_fallback(path: str) -> FileResponse:
        """Serve static files that exist, otherwise fall back to index.html for SPA routing."""
        candidate = STATIC_DIR / path
        if candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(index_path)


app = create_app()
