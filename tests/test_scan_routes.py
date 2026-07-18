from __future__ import annotations

import asyncio
import socket
import warnings
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.config import settings
from app.routes import scan_routes


@pytest.mark.asyncio
async def test_public_target_is_resolved_with_configured_timeout_without_warnings(monkeypatch):
    def resolve_public_target(hostname, port):
        assert hostname == "example.com"
        assert port is None
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(scan_routes.socket, "getaddrinfo", resolve_public_target)
    assert scan_routes.settings is settings
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        await scan_routes._assert_allowed_scan_target("https://example.com")

    assert not [warning for warning in caught if "was never awaited" in str(warning.message)]


@pytest.mark.asyncio
async def test_dns_timeout_returns_controlled_400(monkeypatch):
    def slow_dns_lookup(*args, **kwargs):
        import time

        time.sleep(0.05)
        return []

    monkeypatch.setattr(scan_routes.settings, "INTELLIGENCE_REQUEST_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(scan_routes.socket, "getaddrinfo", slow_dns_lookup)
    with pytest.raises(HTTPException) as exc_info:
        await scan_routes._assert_allowed_scan_target("https://slow-dns.example")

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Unable to resolve scan target"


@pytest.mark.asyncio
async def test_invalid_scan_target_returns_controlled_400():
    with pytest.raises(HTTPException) as exc_info:
        await scan_routes._assert_allowed_scan_target("ftp://example.com")

    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["http://localhost", "http://127.0.0.1", "http://10.0.0.1"])
async def test_localhost_and_private_targets_are_blocked(target):
    with pytest.raises(HTTPException) as exc_info:
        await scan_routes._assert_allowed_scan_target(target)

    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_dns_failure_returns_controlled_400(monkeypatch):
    def dns_failure(*args, **kwargs):
        raise socket.gaierror("DNS lookup failed")

    monkeypatch.setattr(scan_routes.socket, "getaddrinfo", dns_failure)
    with pytest.raises(HTTPException) as exc_info:
        await scan_routes._assert_allowed_scan_target("https://unresolvable.example")

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Unable to resolve scan target"


@pytest.mark.asyncio
async def test_valid_public_url_queues_url_scan_task(monkeypatch):
    scan_id = uuid4()
    queued = []

    def resolve_public_target(hostname, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    class FakeResult:
        def scalar_one(self):
            return 0

    class FakeSession:
        def __init__(self):
            self.added = []
            self.committed = False

        async def execute(self, statement):
            return FakeResult()

        def add(self, model):
            self.added.append(model)

        async def commit(self):
            self.committed = True

        async def refresh(self, model):
            model.id = scan_id

    task = Mock()
    task.delay.side_effect = lambda *args: queued.append(args)
    monkeypatch.setattr(scan_routes.socket, "getaddrinfo", resolve_public_target)
    monkeypatch.setattr("app.celery_app.run_url_scan_task", task)
    db = FakeSession()
    user = SimpleNamespace(id=uuid4(), is_approved=True, scan_limit=10)
    payload = SimpleNamespace(url="https://example.com", project_id=None)

    response = await scan_routes.scan_url_target.__wrapped__(None, payload, db, user)

    assert response.scan_id == scan_id
    assert response.status == "queued"
    assert db.committed is True
    assert len(db.added) == 1
    assert db.added[0].result_metadata == {
        "target": {
            "original_input": "https://example.com",
            "normalized_url": "https://example.com",
            "hostname": "example.com",
            "resolved_public_ips": ["93.184.216.34"],
            "final_redirect_url": "https://example.com",
            "scanable_target_type": "url",
            "redirects_followed": False,
        }
    }
    assert queued == [(str(scan_id), "https://example.com")]
