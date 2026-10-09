"""Minimal stdlib HTTP transport, injectable for tests."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Protocol


class Transport(Protocol):
    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes,
                 timeout: float) -> tuple[int, dict[str, str], bytes]: ...


class TransportTimeout(Exception):
    pass


class TransportConnectError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would turn a signed POST into a GET (body dropped) and could leave HTTPS; surface it as a
    failed delivery instead of following it."""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))


def urllib_transport(method: str, url: str, headers: dict[str, str], body: bytes,
                     timeout: float) -> tuple[int, dict[str, str], bytes]:
    parts = urllib.parse.urlsplit(url)
    local = parts.hostname in ("127.0.0.1", "localhost", "::1")
    if parts.scheme != "https" and not (parts.scheme == "http" and local):
        raise ValueError("refusing non-HTTPS URL outside localhost")
    req = urllib.request.Request(url, data=body if method != "GET" else None, headers=headers, method=method)  # noqa: S310 - scheme checked above
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers.items()), resp.read(1_000_000)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()) if e.headers else {}, e.read(1_000_000) if e.fp else b""
    except TimeoutError as e:
        raise TransportTimeout(str(e)) from e
    except urllib.error.URLError as e:
        if isinstance(e.reason, TimeoutError):
            raise TransportTimeout(str(e)) from e
        raise TransportConnectError(str(e.reason)) from e
