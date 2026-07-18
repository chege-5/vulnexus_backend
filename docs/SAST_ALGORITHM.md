# VulNexus SAST algorithm

VulNexus uses **Rule-Based Context-Aware Static Security Analysis**. It is deterministic regex/static-pattern analysis, not machine learning or full semantic taint analysis.

```text
safe files -> master manifest -> crypto/application/framework packs
           -> compiled language-aware rules -> context/confidence
           -> specificity-first dedupe + redaction -> correlation/risk/report
```

The scanner filters excluded paths and selects rules by normalized language/configuration scope. The versioned `scanner_rules.yml` manifest loads `crypto_rules.yml` and `sast_rules.yml` once through the cached loader; every rule is schema-validated and compiled before matching. Findings retain their canonical rule ID, pack, CWE/OWASP mapping, CVSS hint, confidence, remediation, references, and crypto feature. Nearby context lowers confidence or marks dangerous sinks `requires_review` when regex cannot prove attacker control. Exact duplicates are removed while distinct specific findings remain visible. Secrets are redacted before evidence reaches reports or logs.

Crypto-audit categories are weak hashing, hardcoded keys, insecure randomness, poor key management, TLS configuration, and weak cryptographic modes. Application/framework categories include injection, deserialization, command execution, unsafe templates, JWT/authentication, FastAPI/Express configuration, Node TLS, and cookies/CORS. Supported language mappings include Python, JavaScript/TypeScript, Java/Kotlin, PHP, Ruby, Go, C/C++, shell, YAML/JSON/TOML/INI/Terraform, Nginx, Apache, OpenSSL, and generic files only where rules declare them.

The test suite uses paired vulnerable/benign fixtures, rule-schema tests, canonical-ID and crypto-feature assertions, suppression/deduplication regressions, and redaction checks. Runtime TLS, certificate, HTTP-header absence, cookie flags, and live endpoint behavior remain the URL/TLS/Header scanners' responsibility.

## Why this approach?

It is fast, explainable, modular, auditable, and appropriate for a hybrid cryptographic-auditing platform. Regex findings identify risky patterns or review-needed conditions; they do not automatically prove exploitability, dataflow, control flow, or business impact.

**Pitch answer:** VulNexus uses a rule-based, context-aware static analysis algorithm. It filters files safely, selects language-relevant compiled rules, performs deterministic pattern matching, evaluates nearby security context to adjust confidence, preserves the most specific finding through deduplication, redacts sensitive evidence, and forwards normalized findings to the correlation and risk-scoring engines. This makes the system explainable and fast, while clearly distinguishing pattern detection from confirmed exploitability.
