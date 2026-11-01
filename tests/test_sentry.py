from typing import Any

import pytest
import sentry_sdk

from pypi_tea import sentry


@pytest.fixture()
def captured(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(sentry_sdk, "init", lambda **kw: calls.append(kw))
    monkeypatch.setattr(sentry_sdk, "set_tag", lambda *a: None)
    for var in ("SENTRY_DSN", "SENTRY_TRACES_SAMPLE_RATE", "SENTRY_SEND_DEFAULT_PII"):
        monkeypatch.delenv(var, raising=False)
    return calls


def test_disabled_without_dsn(captured: list[dict[str, Any]]) -> None:
    assert sentry.init("worker") is False
    assert captured == []


def test_enabled_with_dsn(captured: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTRY_DSN", "https://key@sentry.example.com/1")
    assert sentry.init("worker") is True
    [kw] = captured
    assert kw["dsn"] == "https://key@sentry.example.com/1"
    assert kw["release"].startswith("pypi-tea@")
    assert kw["send_default_pii"] is False
    assert kw["traces_sample_rate"] == 0.01


def test_env_overrides(captured: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTRY_DSN", "https://key@sentry.example.com/1")
    monkeypatch.setenv("SENTRY_SEND_DEFAULT_PII", "true")
    monkeypatch.setenv("SENTRY_TRACES_SAMPLE_RATE", "0.5")
    sentry.init("api")
    [kw] = captured
    assert kw["send_default_pii"] is True
    assert kw["traces_sample_rate"] == 0.5
