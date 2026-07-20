from pathlib import Path

import pytest

from app.services.file_scanner import scan_file_content
from app.services.rule_loader import RuleValidationError, load_rule_pack
from app.services.scanners.headers import HeaderScanner


FIXTURES = Path(__file__).parent / "fixtures" / "security_checks"


def _source_ids(content: str, path: str) -> set[str]:
    findings, _ = scan_file_content(content, path)
    return {finding.evidence["source_rule_id"] for finding in findings}


def test_vulnerable_and_benign_sast_regression_fixtures():
    vulnerable = (FIXTURES / "sast_regression_vulnerable.py").read_text(encoding="utf-8")
    benign = (FIXTURES / "sast_regression_benign.py").read_text(encoding="utf-8")
    vulnerable_ids = _source_ids(vulnerable, "fixture.py")
    benign_ids = _source_ids(benign, "fixture.py")
    expected = {"SAST_PY_JINJA_TEMPLATE_UNSAFE", "SAST_PY_HTTPX_VERIFY_FALSE", "SAST_PY_SSL_UNVERIFIED_CONTEXT", "WEAK_HASH_MD5_PY_HASHLIB", "WEAK_CIPHER_AES-ECB", "SAST_PY_STATIC_IV_NONCE", "SAST_FASTAPI_INSECURE_COOKIE_FLAGS", "SAST_SQL_CONCAT", "SAST_PATH_TRAVERSAL"}
    assert expected.issubset(vulnerable_ids)
    assert not expected.intersection(benign_ids)


@pytest.mark.parametrize(("content", "path", "expected", "unexpected"), [
    ('cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))', "db.py", set(), {"SAST_SQL_CONCAT"}),
    ('cursor.execute("SELECT * FROM users WHERE id = " + user_id)', "db.py", {"SAST_SQL_CONCAT"}, set()),
    ('safe = path.join(base, filename)', "routes.js", set(), {"SAST_PATH_TRAVERSAL"}),
    ('fs.readFile(req.query.filename, callback)', "routes.js", {"SAST_PATH_TRAVERSAL"}, set()),
    ('const visual = Math.random()', "ui.js", set(), {"SAST_JS_MATH_RANDOM_TOKEN"}),
    ('const resetToken = Math.random()', "auth.js", {"SAST_JS_MATH_RANDOM_TOKEN"}, set()),
    ('process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"', "server.js", {"SAST_NODE_TLS_REJECT_UNAUTHORIZED_FALSE"}, set()),
    ('jwt.decode(token, options={"verify_signature": False})', "auth.py", {"SAST_JWT_VERIFY_DISABLED"}, set()),
    ('allow_origins=["*"], allow_credentials=True', "app.py", {"SAST_FASTAPI_CORS_WILDCARD_CREDENTIALS"}, set()),
    ('allow_origins=["https://app.example"], allow_credentials=True', "app.py", set(), {"SAST_FASTAPI_CORS_WILDCARD_CREDENTIALS"}),
])
def test_rule_false_positive_regressions(content, path, expected, unexpected):
    ids = _source_ids(content, path)
    assert expected.issubset(ids)
    assert not unexpected.intersection(ids)


def test_gcp_key_evidence_is_redacted():
    findings, _ = scan_file_content('"private_key_id": "fake-key-material-never-usable"', "service.json")
    finding = next(item for item in findings if item.evidence["source_rule_id"] == "SAST_GCP_SERVICE_ACCOUNT_KEY")
    assert "fake-key-material-never-usable" not in str(finding.evidence)
    assert "[REDACTED]" in str(finding.evidence)


def test_rule_validator_rejects_invalid_language_and_empty_recommendation(tmp_path):
    pack = tmp_path / "invalid.yml"
    pack.write_text("""version: '1'\ncategories:\n  test:\n    - {id: BAD, title: Bad, category: Test, severity: High, confidence: 0.8, cvss_hint: 7.5, languages: [brainfuck], regex: x, cwe: [CWE-1], owasp: A01, recommendation: '', references: [https://example.test], enabled: true}\n""", encoding="utf-8")
    with pytest.raises(RuleValidationError):
        load_rule_pack(pack)


def test_runtime_header_scanner_reports_missing_cookie_flags():
    findings = HeaderScanner()._analyze_headers({"set-cookie": "session=opaque"}, "https://example.test/account")
    cookie = next(item for item in findings if item.raw_data["rule_id"] == "INSECURE_COOKIE_FLAGS")
    assert set(cookie.evidence["missing_flags"]) == {"secure", "httponly", "samesite"}
