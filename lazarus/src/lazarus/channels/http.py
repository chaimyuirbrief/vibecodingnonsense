"""Minimal stdlib HTTP transport, injectable for tests."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from typing import Protocol


class Transport(Protocol):
    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes,
                 timeout: float) -> tuple[int, dict[str, str], bytes]: ...


class TransportTimeout(Exception):
    pass


class TransportConnectError(Exception):
    pass


def urllib_transport(method: str, url: str, headers: dict[str, str], body: bytes,
                     timeout: float) -> tuple[int, dict[str, str], bytes]:
    if not url.startswith("https://") and not url.startswith("http://127.0.0.1") and not url.startswith("http://localhost"):
        raise ValueError("refusing non-HTTPS URL outside localhost")
    req = urllib.request.Request(url, data=body if method != "GET" else None, headers=headers, method=method)  # noqa: S310 - scheme checked above
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:  # noqa: S310
            return resp.status, dict(resp.headers.items()), resp.read(1_000_000)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()) if e.headers else {}, e.read(1_000_000) if e.fp else b""
    except TimeoutError as e:
        raise TransportTimeout(str(e)) from e
    except urllib.error.URLError as e:
        if isinstance(e.reason, TimeoutError):
            raise TransportTimeout(str(e)) from e
        raise TransportConnectError(str(e.reason)) from e
