#!/usr/bin/env python3
"""Minimal log shipper for Vigil.

Reads a log file (optionally following it like ``tail -F``) and posts batches of raw
lines to ``POST /api/events/raw``. Uses only the standard library so it can run on any
host with Python 3.9+.

    export VIGIL_INGEST_TOKEN=...
    python tools/ship_logs.py /var/log/auth.log --url http://siem:8080 --follow
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request


def post(url: str, token: str, lines: list[str], host: str) -> dict:
    body = json.dumps({"text": "\n".join(lines), "host": host}).encode()
    req = urllib.request.Request(
        f"{url.rstrip('/')}/api/events/raw",
        data=body,
        headers={"Content-Type": "application/json", "X-Ingest-Token": token},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def read_lines(path: str, follow: bool):
    with open(path, encoding="utf-8", errors="replace") as fh:
        if follow:
            fh.seek(0, os.SEEK_END)
        while True:
            line = fh.readline()
            if line:
                yield line.rstrip("\n")
            elif follow:
                yield None  # idle tick so pending batches get flushed
                time.sleep(0.5)
                # handle rotation / truncation
                try:
                    if os.stat(path).st_size < fh.tell():
                        fh.seek(0)
                except FileNotFoundError:
                    pass
            else:
                return


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("path", help="log file to ship")
    parser.add_argument("--url", default=os.getenv("VIGIL_URL", "http://localhost:8080"))
    parser.add_argument("--token", default=os.getenv("VIGIL_INGEST_TOKEN"))
    parser.add_argument("--host", default=socket.gethostname(), help="default host for lines without one")
    parser.add_argument("--follow", "-f", action="store_true", help="keep reading new lines")
    parser.add_argument("--batch", type=int, default=500, help="max lines per request")
    args = parser.parse_args()

    if not args.token:
        parser.error("an ingest token is required (--token or VIGIL_INGEST_TOKEN)")

    batch: list[str] = []
    last_flush = time.monotonic()
    shipped = 0

    def flush() -> None:
        nonlocal batch, last_flush, shipped
        if not batch:
            return
        for attempt in range(5):
            try:
                result = post(args.url, args.token, batch, args.host)
                shipped += result["accepted"]
                if result["alerts_created"]:
                    print(f"[vigil] {result['alerts_created']} new alert(s)", file=sys.stderr)
                break
            except (urllib.error.URLError, TimeoutError) as exc:
                wait = 2**attempt
                print(f"[vigil] send failed ({exc}); retrying in {wait}s", file=sys.stderr)
                time.sleep(wait)
        batch = []
        last_flush = time.monotonic()

    try:
        for line in read_lines(args.path, args.follow):
            if line:
                batch.append(line)
            if len(batch) >= args.batch or (batch and time.monotonic() - last_flush > 2):
                flush()
        flush()
    except KeyboardInterrupt:
        flush()
    print(f"[vigil] shipped {shipped} events", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
