"""Sentry error tracking, shared by the API and the worker.

Configured with Sentry's own environment variables so the same deployment file
serves both processes: `SENTRY_DSN` (unset disables Sentry), and optionally
`SENTRY_ENVIRONMENT`, `SENTRY_TRACES_SAMPLE_RATE` and `SENTRY_SEND_DEFAULT_PII`.
"""

import os
from importlib.metadata import version

import sentry_sdk


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def init(component: str) -> bool:
    """Start Sentry for this process, tagged with `component` ("api", "worker", ...). Returns whether it's enabled."""
    dsn = os.environ.get("SENTRY_DSN", "").strip()
    if not dsn:
        return False
    sentry_sdk.init(
        dsn=dsn,
        release=f"pypi-tea@{version('pypi-tea')}",
        traces_sample_rate=float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0.01")),
        # Off by default: the API is public and anonymous, so request headers and
        # client IPs are the only "user" data there is, and none of it is ours to keep.
        send_default_pii=_flag("SENTRY_SEND_DEFAULT_PII"),
    )
    sentry_sdk.set_tag("component", component)
    return True
