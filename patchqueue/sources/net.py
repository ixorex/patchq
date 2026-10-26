"""Tiny HTTPS client on urllib. Honors HTTPS_PROXY. Size-capped, retried, no telemetry."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from .. import __version__

MAX_BYTES = 64 * 1024 * 1024
RETRY_SLEEP = 1.5


class FetchError(Exception):
    pass


def fetch(url: str, payload=None, headers=None, timeout: int = 30, retries: int = 2) -> bytes:
    if not url.startswith("https://"):
        raise FetchError(f"refusing non-HTTPS URL: {url}")
    data = json.dumps(payload).encode() if payload is not None else None
    h = {"User-Agent": f"patchq/{__version__}", "Accept": "application/json"}
    if data is not None:
        h["Content-Type"] = "application/json"
    h.update(headers or {})
    last = "unknown error"
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=data, headers=h, method="POST" if data is not None else "GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise FetchError(f"{url}: response larger than {MAX_BYTES} bytes")
            return body
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            if e.code not in (429, 500, 502, 503, 504):
                break
        except (urllib.error.URLError, OSError) as e:
            last = str(getattr(e, "reason", e))
        if attempt < retries:
            time.sleep(RETRY_SLEEP * (attempt + 1))
    raise FetchError(f"{url.split('?')[0]}: {last}")


def fetch_json(url: str, payload=None, headers=None, timeout: int = 30):
    body = fetch(url, payload=payload, headers=headers, timeout=timeout)
    try:
        return json.loads(body)
    except ValueError as e:
        raise FetchError(f"{url.split('?')[0]}: invalid JSON ({e})")
