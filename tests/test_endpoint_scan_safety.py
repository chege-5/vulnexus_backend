import asyncio
from uuid import uuid4

from app.services.models.pipeline import ScanContext, ScanTarget
from app.services.scanners.headers import HeaderScanner
from app.services.scanners.technology import TechnologyFingerprintScanner
from app.services.scanners.web_crawl import WebCrawlScanner


def test_endpoint_scanners_disable_redirect_following(monkeypatch):
    observed = []

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    def fake_client(**kwargs):
        observed.append(kwargs)
        return DummyClient()

    async def no_response(*args, **kwargs):
        return None

    monkeypatch.setattr("app.services.scanners.headers.create_async_client", fake_client)
    monkeypatch.setattr("app.services.scanners.technology.create_async_client", fake_client)
    monkeypatch.setattr("app.services.scanners.web_crawl.create_async_client", fake_client)
    monkeypatch.setattr("app.services.scanners.headers.request_with_retry", no_response)
    monkeypatch.setattr("app.services.scanners.technology.request_with_retry", no_response)
    monkeypatch.setattr("app.services.scanners.web_crawl.request_with_retry", no_response)

    target = ScanTarget(kind="url", value="https://example.com")
    context = ScanContext(scan_id=uuid4(), scan_type="url", target=target)
    for scanner in (HeaderScanner(), TechnologyFingerprintScanner(), WebCrawlScanner()):
        asyncio.run(scanner.scan(target, context))

    assert len(observed) == 3
    assert all(call["follow_redirects"] is False for call in observed)
