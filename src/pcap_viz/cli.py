from __future__ import annotations

import threading
import webbrowser
from pathlib import Path
from typing import Annotated

import typer
import uvicorn

from .parser import parse_pcap
from .server import create_app

app = typer.Typer(add_completion=False, help="Local SIP ladder-diagram viewer.")


@app.command()
def main(
    pcap: Annotated[
        Path | None,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Optional .pcap/.pcapng to pre-load.",
        ),
    ] = None,
    port: Annotated[int, typer.Option("--port", "-p", help="Port to bind.")] = 8765,
    host: Annotated[str, typer.Option(help="Host interface.")] = "127.0.0.1",
    no_browser: Annotated[
        bool, typer.Option("--no-browser", help="Don't auto-open a browser window.")
    ] = False,
) -> None:
    """Launch pcap-viz and, if given a pcap, render its ladder in a browser."""
    preload = None
    url = f"http://{host}:{port}/"

    if pcap is not None:
        typer.echo(f"Parsing {pcap}...")
        preload = parse_pcap(pcap)
        typer.echo(
            f"  {preload.sip_message_count} SIP messages across {len(preload.calls)} call(s)."
        )
        # The frontend reads ?preload=1 and fetches /api/preload to find the session.
        url = f"http://{host}:{port}/?preload=1"

    fastapi_app = create_app(preload=preload)

    if not no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
        typer.echo(f"Opening {url}")
    else:
        typer.echo(f"Serving at {url}")

    uvicorn.run(fastapi_app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    app()
