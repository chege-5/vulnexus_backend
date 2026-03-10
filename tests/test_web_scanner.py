import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from app.services.web_scanner import _analyze_tls, _extract_features, _check_security_headers
from app.utils.tls_utils import TLSInfo


def test_weak_tls_version():
    tls = TLSInfo(tls_version="TLSv1", cipher_suite="RC4-SHA", cipher_bits=128, self_signed=False, forward_secrecy=False)
    vulns = _analyze_tls(tls, False, "https://example.com")
    rule_ids = [v.rule_id for v in vulns]
    assert "WEAK_TLS_VERSION" in rule_ids
    assert "NO_FORWARD_SECRECY" in rule_ids
    assert "NO_HSTS" in rule_ids


def test_self_signed_cert():
    tls = TLSInfo(tls_version="TLSv1.2", cipher_suite="ECDHE-RSA-AES256-GCM-SHA384",
                  cipher_bits=256, self_signed=True, forward_secrecy=True)
    vulns = _analyze_tls(tls, True, "https://example.com")
    assert any(v.rule_id == "SELF_SIGNED_CERT" for v in vulns)


def test_expired_cert():
    tls = TLSInfo(tls_version="TLSv1.2", cipher_suite="ECDHE-RSA-AES256-GCM-SHA384",
                  cipher_bits=256, cert_expired=True, forward_secrecy=True)
    vulns = _analyze_tls(tls, True, "https://example.com")
    assert any(v.rule_id == "EXPIRED_CERT" for v in vulns)


def test_good_tls_no_vulns():
    tls = TLSInfo(tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384",
                  cipher_bits=256, self_signed=False, forward_secrecy=True, cert_expired=False)
    vulns = _analyze_tls(tls, True, "https://example.com")
    assert len(vulns) == 0


def test_weak_cipher_detection():
    tls = TLSInfo(tls_version="TLSv1.2", cipher_suite="DES-CBC3-SHA",
                  cipher_bits=112, self_signed=False, forward_secrecy=True)
    vulns = _analyze_tls(tls, True, "https://example.com")
    assert any(v.rule_id == "WEAK_CIPHER_SUITE" for v in vulns)


def test_extract_features():
    tls = TLSInfo(tls_version="TLSv1.2", cipher_suite="ECDHE-RSA-AES256-GCM-SHA384",
                  cipher_bits=256, cert_valid_days=365, forward_secrecy=True, self_signed=False)
    f = _extract_features(tls, True)
    assert f.tls_version == "TLSv1.2"
    assert f.forward_secrecy is True
    assert f.has_hsts is True
    assert f.cert_valid_days == 365


@pytest.mark.asyncio
async def test_check_security_headers_mock():
    with patch("app.services.web_scanner.httpx.AsyncClient") as mock_client_cls:
        mock_response = MagicMock()
        mock_response.headers = {}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_client
        mock_context.__aexit__.return_value = None
        mock_client_cls.return_value = mock_context

        vulns = await _check_security_headers("https://example.com")
        assert any(v.rule_id == "MISSING_X_CONTENT_TYPE" for v in vulns)
