from __future__ import annotations

import asyncio
import ssl
import time
from typing import Any

import certifi
import httpx

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


def build_ssl_context() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=certifi.where())


def _resolve_timeout(timeout: float | httpx.Timeout | None) -> httpx.Timeout:
    if isinstance(timeout, httpx.Timeout):
        return timeout
    if timeout is None:
        timeout = settings.INTELLIGENCE_REQUEST_TIMEOUT_SECONDS
    return httpx.Timeout(timeout)


def create_async_client(
    *,
    timeout: float | httpx.Timeout | None = None,
    headers: dict[str, str] | None = None,
    verify: ssl.SSLContext | bool | str | None = None,
    follow_redirects: bool = True,
    http2: bool = True,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        verify=build_ssl_context() if verify is None else verify,
        timeout=_resolve_timeout(timeout),
        headers=headers,
        follow_redirects=follow_redirects,
        http2=http2,
    )


def create_sync_client(
    *,
    timeout: float | httpx.Timeout | None = None,
    headers: dict[str, str] | None = None,
    verify: ssl.SSLContext | bool | str | None = None,
    follow_redirects: bool = True,
    http2: bool = True,
) -> httpx.Client:
    return httpx.Client(
        verify=build_ssl_context() if verify is None else verify,
        timeout=_resolve_timeout(timeout),
        headers=headers,
        follow_redirects=follow_redirects,
        http2=http2,
    )


def _is_ssl_verification_error(exc: Exception) -> bool:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return True
    if isinstance(exc, httpx.ConnectError):
        message = str(exc).lower()
        if "certificate verify failed" in message or "unable to get local issuer certificate" in message:
            return True
    cause = getattr(exc, "__cause__", None)
    if isinstance(cause, ssl.SSLError):
        message = str(cause).lower()
        if "certificate verify failed" in message or "unable to get local issuer certificate" in message:
            return True
    return False


def _is_transient_error(exc: Exception) -> bool:
    if _is_ssl_verification_error(exc):
        return False
    return isinstance(exc, (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError, httpx.TransportError))


async def request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    retries: int | None = None,
    backoff_seconds: float | None = None,
    logger_override=None,
    **kwargs: Any,
) -> httpx.Response | None:
    active_logger = logger_override or logger
    attempts = max(1, retries or settings.INTELLIGENCE_RETRY_ATTEMPTS)
    base_delay = backoff_seconds if backoff_seconds is not None else settings.INTELLIGENCE_RETRY_BACKOFF_SECONDS

    for attempt in range(attempts):
        try:
            return await client.request(method, url, **kwargs)
        except Exception as exc:  # pragma: no cover - network conditions are environment dependent
            if _is_ssl_verification_error(exc):
                active_logger.warning("SSL verification failed for %s %s: %s", method, url, exc)
                return None
            if _is_transient_error(exc) and attempt + 1 < attempts:
                delay = base_delay * (2**attempt)
                active_logger.warning("Transient HTTP error for %s %s (attempt %s/%s): %s", method, url, attempt + 1, attempts, exc)
                await asyncio.sleep(delay)
                continue
            active_logger.warning("HTTP request failed for %s %s: %s", method, url, exc)
            return None

    return None


def request_with_retry_sync(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    retries: int | None = None,
    backoff_seconds: float | None = None,
    logger_override=None,
    **kwargs: Any,
) -> httpx.Response | None:
    active_logger = logger_override or logger
    attempts = max(1, retries or settings.INTELLIGENCE_RETRY_ATTEMPTS)
    base_delay = backoff_seconds if backoff_seconds is not None else settings.INTELLIGENCE_RETRY_BACKOFF_SECONDS

    for attempt in range(attempts):
        try:
            return client.request(method, url, **kwargs)
        except Exception as exc:  # pragma: no cover - network conditions are environment dependent
            if _is_ssl_verification_error(exc):
                active_logger.warning("SSL verification failed for %s %s: %s", method, url, exc)
                return None
            if _is_transient_error(exc) and attempt + 1 < attempts:
                delay = base_delay * (2**attempt)
                active_logger.warning("Transient HTTP error for %s %s (attempt %s/%s): %s", method, url, attempt + 1, attempts, exc)
                time.sleep(delay)
                continue
            active_logger.warning("HTTP request failed for %s %s: %s", method, url, exc)
            return None

    return None
