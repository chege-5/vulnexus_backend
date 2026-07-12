# VulNexus Supervisor Demo Notes

VulNexus currently uses regex-based static analysis, active TLS probing, and HTTP header inspection to detect representative examples of the seven documented security weakness categories. Detection breadth is being expanded through additional rules, semantic analysis, and language-specific parsers.

## What to Click

1. Start the backend and frontend.
2. Open the VulNexus UI and choose a file or repository scan.
3. Upload or scan `tests/fixtures/security_checks`.
4. Open the completed scan result.
5. Confirm the findings table shows category, title, severity, confidence, affected file or URL, masked evidence, explanation, recommendation, and CWE/OWASP mapping where available.
6. Download the report and compare it with `demo_samples/vulnexus_demo_report.html` if a pre-generated artifact is needed.

## What Each Finding Proves

- Weak hashing: `weak_hashing_sample.py` uses `hashlib.md5` and CRC32 in token logic.
- Hardcoded keys: `hardcoded_keys_sample.env` contains cloud-style keys, JWT secrets, and a database URL with masked evidence.
- Insecure randomness: `insecure_randomness_sample.js` uses `Math.random` and `Date.now` to build a reset token.
- Poor key management: `poor_key_management_sample.yml` contains static IV, static salt, hardcoded encryption key, and weak JWT secret.
- TLS misconfiguration: `tls_demo_target_notes.md` documents the TLS demo target behavior; tests simulate weak TLS and weak cipher findings.
- Missing secure headers: `missing_headers_demo.json` demonstrates missing and weak CSP, HSTS, X-Frame-Options, and Cache-Control checks.
- Weak cryptographic modes: `weak_crypto_modes_sample.py` uses AES-ECB, CBC without visible authentication, 3DES, RC4, and a 1024-bit RSA key.

The demo is intentionally representative rather than production-complete. Findings should be described as regex/static-analysis, TLS probing, and header-inspection results.
