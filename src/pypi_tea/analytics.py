"""Product analytics: what TEA clients and visitors actually look up, sent to PostHog.

`capture()` only puts the event on the SDK's in-memory queue; a background
thread batches the uploads, so a request never waits on PostHog, and a full
queue drops events rather than growing.

Nobody signs in, so there are no people to identify. Each client gets an
anonymous id that changes every day: a keyed hash of its IP and User-Agent.
Neither is sent, and events are personless, so the id only ties together one
client's requests within a day.

HTML pages and SBOM downloads are mostly answered by the edge cache, so the
server only sees cache misses for those; the browser snippet in
`templates/_analytics.html` covers what visitors do on the site.
"""

import hashlib
import hmac
import logging
import re
import secrets
import time
from contextvars import ContextVar
from dataclasses import dataclass
from importlib.metadata import version as pkg_version
from typing import Any

from posthog import Posthog

from pypi_tea import db, store
from pypi_tea.config import settings

logger = logging.getLogger("pypi_tea.analytics")

_SALT_KEY = "analytics_salt"
DAY = 86400

_CLIENTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("libtea", re.compile(r"\b(?:py-)?libtea/(\S+)", re.I)),
    ("tea-cli", re.compile(r"\btea-cli/(\S+)", re.I)),
    ("pypi-tea", re.compile(r"\bpypi-tea/(\S+)", re.I)),
    ("python-httpx", re.compile(r"\bpython-httpx/(\S+)", re.I)),
    ("python-requests", re.compile(r"\bpython-requests/(\S+)", re.I)),
    ("python-urllib", re.compile(r"\bPython-urllib/(\S+)", re.I)),
    ("aiohttp", re.compile(r"\baiohttp/(\S+)", re.I)),
    ("curl", re.compile(r"\bcurl/(\S+)", re.I)),
    ("wget", re.compile(r"\bWget/(\S+)", re.I)),
    ("go", re.compile(r"\bGo-http-client/(\S+)", re.I)),
    ("node", re.compile(r"\b(?:node-fetch|undici|axios)/?(\S*)", re.I)),
    ("bot", re.compile(r"(bot|crawler|spider|slurp)\b", re.I)),
    ("browser", re.compile(r"\bMozilla/(\S+)", re.I)),
)


@dataclass(frozen=True)
class RequestContext:
    distinct_id: str
    client: str
    client_version: str | None
    path: str


_request: ContextVar[RequestContext | None] = ContextVar("pypi_tea_analytics_request", default=None)
_client: Posthog | None = None
_salt: bytes = b""


def enabled() -> bool:
    return bool(settings.posthog_api_key)


def init() -> None:
    """Create the PostHog client and load the id salt. Call once per process, after the schema exists."""
    global _client, _salt
    if not enabled() or _client is not None:
        return
    conn = db.writer(settings.database_path)
    # Shared by every API process through the database, so a client keeps one id across them.
    conn.execute("INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)", (_SALT_KEY, secrets.token_hex(32)))
    _salt = bytes.fromhex(store.get_meta(conn, _SALT_KEY) or "")
    _client = Posthog(
        settings.posthog_api_key,
        host=settings.posthog_host,
        disable_geoip=True,
        super_properties={"app": "pypi-tea", "app_version": pkg_version("pypi-tea")},
    )


def shutdown() -> None:
    global _client
    if _client is None:
        return
    try:
        _client.shutdown()
    except Exception:
        logger.warning("posthog shutdown failed", exc_info=True)
    _client = None


def classify_client(user_agent: str) -> tuple[str, str | None]:
    """User-Agent -> (client family, version). Only these two leave the process, never the raw header."""
    for name, pattern in _CLIENTS:
        m = pattern.search(user_agent)
        if m:
            version = m.group(1) if name not in ("bot", "browser") and m.groups() else None
            return name, (version or None)
    return ("unknown", None) if user_agent else ("none", None)


def anonymous_id(ip: str, user_agent: str, now: float | None = None) -> str:
    day = int((time.time() if now is None else now) // DAY)
    digest = hmac.new(_salt, f"{day}\0{ip}\0{user_agent}".encode(), hashlib.sha256).hexdigest()
    return f"anon-{digest[:32]}"


def begin_request(ip: str, user_agent: str, path: str) -> None:
    """Bind the caller of the current request, so events captured while handling it are attributed to it."""
    if _client is None:
        return
    client, client_version = classify_client(user_agent)
    _request.set(RequestContext(anonymous_id(ip, user_agent), client, client_version, path))


def capture(event: str, properties: dict[str, Any] | None = None, distinct_id: str | None = None) -> None:
    """Queue one event. Never raises: analytics must not be able to fail a request or a job."""
    if _client is None:
        return
    props: dict[str, Any] = {"$process_person_profile": False}
    ctx = _request.get()
    if ctx is not None:
        props.update(client=ctx.client, client_version=ctx.client_version, path=ctx.path)
        distinct_id = distinct_id or ctx.distinct_id
    if properties:
        props.update(properties)
    try:
        _client.capture(event, distinct_id=distinct_id or "pypi-tea", properties=props)
    except Exception:
        logger.warning("posthog capture failed", exc_info=True)
