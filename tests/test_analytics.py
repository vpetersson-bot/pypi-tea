"""PostHog analytics: client classification, anonymous ids, and the events the API, pages and worker send."""

from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest

from conftest import FakePyPI, sbom_wheel
from pypi_tea import analytics, db, jobs, store, worker
from pypi_tea.app import app
from pypi_tea.config import settings
from pypi_tea.ingest import ingest_release
from pypi_tea.routes import pages

pytestmark = pytest.mark.anyio

UA = "py-libtea/0.4.1 (python-httpx/0.28.1)"


class FakePostHog:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def capture(self, event: str, *, distinct_id: str, properties: dict[str, Any]) -> None:
        self.events.append({"event": event, "distinct_id": distinct_id, "properties": properties})

    def named(self, event: str) -> list[dict[str, Any]]:
        return [e for e in self.events if e["event"] == event]


@pytest.fixture()
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture()
def posthog(monkeypatch: pytest.MonkeyPatch) -> FakePostHog:
    fake = FakePostHog()
    monkeypatch.setattr(settings, "posthog_api_key", "phc_test")
    monkeypatch.setattr(analytics, "_client", fake)
    monkeypatch.setattr(analytics, "_salt", b"test-salt")
    return fake


@pytest.fixture()
async def client(database: str) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, client=("203.0.113.7", 1234))
    async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"User-Agent": UA}) as c:
        yield c


async def _seed(fake_pypi: FakePyPI, name: str, version: str) -> None:
    fake_pypi.add(name, version, [(f"{name}-{version}-py3-none-any.whl", sbom_wheel(name, version))])
    async with fake_pypi.client() as c:
        await ingest_release(c, name, version)
    store.rebuild_listing(db.connect(settings.database_path))


@pytest.mark.parametrize(
    ("user_agent", "expected"),
    [
        ("py-libtea/0.4.1 (python-httpx/0.28.1)", ("libtea", "0.4.1")),
        ("python-httpx/0.28.1", ("python-httpx", "0.28.1")),
        ("python-requests/2.32.3", ("python-requests", "2.32.3")),
        ("curl/8.5.0", ("curl", "8.5.0")),
        ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", ("bot", None)),
        ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36", ("browser", None)),
        ("something-else", ("unknown", None)),
        ("", ("none", None)),
    ],
)
def test_classify_client(user_agent: str, expected: tuple[str, str | None]) -> None:
    assert analytics.classify_client(user_agent) == expected


def test_anonymous_id_rotates_daily(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(analytics, "_salt", b"salt")
    day = 1_700_000_000 // analytics.DAY * analytics.DAY
    same_day = analytics.anonymous_id("203.0.113.7", UA, day + 10)
    assert same_day == analytics.anonymous_id("203.0.113.7", UA, day + 80_000)
    assert same_day != analytics.anonymous_id("203.0.113.7", UA, day + analytics.DAY)
    assert same_day != analytics.anonymous_id("203.0.113.8", UA, day + 10)
    assert "203.0.113.7" not in same_day


def test_init_shares_one_salt_across_processes(database: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "posthog_api_key", "phc_test")
    analytics.init()
    first = analytics._salt
    analytics.shutdown()
    analytics.init()
    try:
        assert first and analytics._salt == first
    finally:
        analytics.shutdown()


def test_capture_is_a_noop_when_disabled(database: str) -> None:
    assert analytics._client is None
    analytics.capture("anything", {"x": 1})  # must not raise


async def test_discovery_sends_tagged_lookup(
    client: httpx.AsyncClient, fake_pypi: FakePyPI, posthog: FakePostHog
) -> None:
    await _seed(fake_pypi, "maturin", "1.8.1")
    resp = await client.get("/discovery", params={"tei": "urn:tei:purl:x:pkg:pypi/maturin@1.8.1?os=linux"})
    assert resp.status_code == 200

    [lookup] = posthog.named("sbom_lookup")
    props = lookup["properties"]
    assert props["source"] == "discovery"
    assert (props["package"], props["version"], props["os"]) == ("maturin", "1.8.1", "linux")
    assert props["platform_qualified"] is True
    assert props["has_sbom"] is True
    assert props["sbom_formats"] == ["CycloneDX"]
    assert props["client"] == "libtea"
    assert props["$process_person_profile"] is False
    assert lookup["distinct_id"].startswith("anon-")

    [call] = posthog.named("tea_api_called")
    assert call["properties"]["endpoint"] == "discovery"
    assert call["properties"]["status_code"] == 200
    assert call["distinct_id"] == lookup["distinct_id"]
    # Neither the address nor the raw User-Agent leaves the process.
    for event in posthog.events:
        assert "203.0.113.7" not in repr(event)
        assert UA not in repr(event)


async def test_failed_lookups_carry_a_reason(client: httpx.AsyncClient, posthog: FakePostHog) -> None:
    await client.get("/discovery", params={"tei": "urn:tei:uuid:x:d4d9f54a-abcf-11ee-ac79-1a52914d44b1"})
    await client.get("/productReleases", params={"idType": "PURL", "idValue": "pkg:pypi/requests"})
    reasons = [e["properties"]["reason"] for e in posthog.named("sbom_lookup_failed")]
    assert reasons == ["unsupported_tei", "unversioned"]


async def test_download_is_tracked_with_package(
    client: httpx.AsyncClient, fake_pypi: FakePyPI, posthog: FakePostHog
) -> None:
    await _seed(fake_pypi, "maturin", "1.8.1")
    release = store.get_release(db.connect(settings.database_path), "maturin", "1.8.1")
    assert release is not None
    uuid = release.wheels[0].sboms[0].uuid
    resp = await client.get(f"/artifact/{uuid}/download")
    assert resp.status_code == 200
    [download] = posthog.named("sbom_downloaded")
    assert download["properties"]["package"] == "maturin"
    assert download["properties"]["artifact_uuid"] == uuid


async def test_pages_and_stats_send_no_server_events(
    client: httpx.AsyncClient, fake_pypi: FakePyPI, posthog: FakePostHog
) -> None:
    await _seed(fake_pypi, "maturin", "1.8.1")
    for path in ("/package/maturin/1.8.1", "/packages", "/stats", "/healthz", "/robots.txt"):
        await client.get(path)
    assert posthog.events == []


async def test_package_page_tags_browser_events(
    client: httpx.AsyncClient, fake_pypi: FakePyPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _seed(fake_pypi, "maturin", "1.8.1")
    monkeypatch.setattr(settings, "posthog_api_key", "phc_test")
    html = (await client.get("/package/maturin/1.8.1")).text
    assert 'posthog.init("phc_test"' in html
    assert '"page_type": "package"' in html
    assert '"package": "maturin"' in html
    assert 'data-ph-event="sbom_download_clicked"' in html
    assert 'data-ph-sbom-format="CycloneDX"' in html


async def test_no_browser_snippet_when_disabled(client: httpx.AsyncClient, fake_pypi: FakePyPI) -> None:
    await _seed(fake_pypi, "maturin", "1.8.1")
    html = (await client.get("/package/maturin/1.8.1")).text
    assert "posthog" not in html
    assert "posthog" not in pages.render("_analytics.html")


async def test_worker_reports_on_demand_indexing(database: str, fake_pypi: FakePyPI, posthog: FakePostHog) -> None:
    fake_pypi.add("newpkg", "1.0", [("newpkg-1.0-py3-none-any.whl", sbom_wheel("newpkg", "1.0"))])
    fake_pypi.add("bulk", "1.0", [("bulk-1.0-py3-none-any.whl", sbom_wheel("bulk", "1.0"))])
    async with fake_pypi.client() as c:
        await worker.run_job(c, jobs.Job(1, "newpkg", "1.0", jobs.PRIORITY_INTERACTIVE, 1))
        await worker.run_job(c, jobs.Job(2, "bulk", "1.0", jobs.PRIORITY_BACKFILL, 1))
    [indexed] = posthog.named("release_indexed")
    assert indexed["distinct_id"] == "pypi-tea-worker"
    assert indexed["properties"]["package"] == "newpkg"
    assert indexed["properties"]["has_sbom"] is True
    assert indexed["properties"]["trigger"] == "lookup"
