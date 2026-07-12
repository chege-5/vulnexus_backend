# VulNexus — Cryptography and Security Weakness Scanner (Backend)

Backend system that scans source code and live websites for representative cryptographic, transport, secrets, and secure-header weaknesses, then generates audit reports for review.

VulNexus currently uses regex-based static analysis, active TLS probing, and HTTP header inspection to detect representative examples of the seven documented security weakness categories. Detection breadth is being expanded through additional rules, semantic analysis, and language-specific parsers.

## Architecture

```
User Input -> Static Code Scanner -> Web TLS Scanner -> Header Scanner
    -> Rule Engine -> Report Generator -> API Response
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| API Framework | FastAPI (async) |
| Database | PostgreSQL + SQLAlchemy (async) |
| Schema setup | Alembic migrations with startup revision checks |
| ML | Deterministic scoring with optional experimental model utilities |
| Reports | Playwright/Chromium PDF rendering + Jinja2 HTML |
| Performance | Python scanner implementation |
| Caching | In-memory / Redis |
| Deployment | Docker Compose |

## Quick Start

### 1. Clone and configure

```bash
cp .env.example .env
# Edit .env with your settings
```

### 2. Start with Docker

```bash
docker-compose up --build -d
```

### 3. Initialize database schema

```bash
docker-compose exec backend python scripts/init_db.py
```

### 4. Access API

- API: http://localhost:8000
- Docs: http://localhost:8000/docs
- Health: http://localhost:8000/healthz
- Metrics: http://localhost:8000/metrics

## Local Development

```bash
python -m venv venv
venv\Scripts\activate      # Windows
pip install -r requirements.txt

# Start PostgreSQL locally (or use Docker), then:
python scripts/init_db.py
python scripts/train_model.py
uvicorn app.main:app --reload
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/upload-file` | Upload source code / ZIP for scanning |
| POST | `/api/v1/scan-url` | Scan a website's TLS configuration |
| GET | `/api/v1/scan-status/{scan_id}` | Check scan progress |
| GET | `/api/v1/scan-result/{scan_id}` | Get scan results with vulnerabilities |
| GET | `/api/v1/report/{scan_id}` | Download PDF/HTML audit report |
| GET | `/api/v1/dashboard` | Dashboard summary statistics |
| GET | `/healthz` | Health check |
| GET | `/metrics` | Prometheus metrics |

## Project Structure

```
backend/
├── app/
│   ├── main.py                 # FastAPI application
│   ├── config.py               # Settings management
│   ├── deps.py                 # PostgreSQL session + dependencies
│   ├── database.py             # SQLAlchemy engine and schema init
│   ├── routes/
│   │   ├── scan_routes.py      # Upload/scan endpoints
│   │   ├── report_routes.py    # Report download endpoint
│   │   └── dashboard_routes.py # Dashboard endpoint
│   ├── services/
│   │   ├── file_scanner.py     # Static code analysis
│   │   ├── web_scanner.py      # TLS/web scanning
│   │   ├── rule_engine.py      # Rule-based vulnerability detection
│   │   ├── ai_risk_model.py    # ML training & inference
│   │   ├── cve_mapper.py       # CVE lookup (MITRE/NVD/CIRCL)
│   │   ├── report_generator.py # HTML/PDF report generation
│   │   └── tasks.py            # Scan orchestration
│   ├── models/
│   │   ├── db_models.py        # SQLAlchemy ORM models
│   │   ├── pydantic_models.py  # Request/response schemas
│   │   └── ml_models.py        # ML feature definitions
│   └── utils/
│       ├── file_utils.py       # File upload/extraction
│       ├── tls_utils.py        # TLS connection analysis
│       ├── logger.py           # Structured logging
│       └── cache.py            # Simple caching layer
├── tests/
│   ├── test_file_scanner.py
│   ├── test_web_scanner.py
│   ├── test_ai_model.py
│   └── test_integration.py
├── scripts/
│   ├── train_model.py
│   └── init_db.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

## Scanning Capabilities

### Static Code Scanner
- Hardcoded keys and secrets
- Weak hash algorithms (MD5, SHA-1)
- Weak ciphers and modes (AES-ECB, DES, 3DES, RC2, RC4, Blowfish, unauthenticated CBC)
- Insecure random number generators
- Small RSA keys (< 2048 bits)
- Small AES keys (< 128 bits)
- Private key detection
- Poor key management indicators such as static IVs, static salts, weak JWT secrets, and config-stored secrets

### Web TLS Scanner
- TLS version detection
- Cipher suite strength
- Certificate validity & expiry
- Self-signed certificate detection
- Forward secrecy support
- HSTS header presence
- Security headers (CSP, X-Frame-Options, etc.)
- SSL Labs integration

## External APIs

| API | Purpose | Required |
|-----|---------|----------|
| MITRE CVE | CVE descriptions | No (best effort) |
| NVD | CVE metadata + CVSS | No (best effort) |
| CIRCL CVE | Fallback CVE search | No (best effort) |
| SSL Labs | TLS grading | No (optional) |
| Shodan | Infrastructure scanning | No (feature flag) |
| VirusTotal | Malware analysis | No (feature flag) |
| OpenAI | AI remediation text | No (feature flag) |

## Scoring

- Deterministic rules assign severity, confidence, remediation, and CWE/OWASP mapping where available.
- Experimental model utilities may be used during research, but the demo path does not depend on machine-learning classification.

## Testing

```bash
pytest tests/ -v
pytest tests/ -v --cov=app --cov-report=html
```

## Database Schema

- `users` — User accounts
- `scans` — Scan jobs (file/URL, status, score)
- `scan_files` — Files within a scan
- `vulnerabilities` — Detected issues with severity/CVE mapping
- `cve_entries` — Cached CVE data
- `ml_features` — Feature vectors for model retraining

### Database migrations

`DATABASE_URL` is the single source of truth for FastAPI and Alembic. It must
point to PostgreSQL using `postgresql+asyncpg://user:pass@host:5432/dbname`.
`postgresql://` URLs are normalized automatically. `ASYNC_DATABASE_URL`, when
retained for backward compatibility, must match `DATABASE_URL`.

Install dependencies and bring any new or existing database to the current
revision before starting the API:

```powershell
python -m pip install -r requirements.txt
python -m alembic upgrade head
python -m alembic current
python -m uvicorn app.main:app --reload
```

Useful inspection and migration commands:

```powershell
python -m alembic current
python -m alembic heads
python -m alembic history
python -m alembic check
python -m alembic revision --autogenerate -m "description"
python -m alembic upgrade head
python -m alembic downgrade -1
```

Review every autogenerated migration before applying it. Production migrations
should be run as a deployment step before new application instances start; the
application deliberately refuses to start when its database revision is behind
the Alembic head. Never use `Base.metadata.create_all()` as a migration system:
it can create missing tables but cannot add or alter columns in existing tables.

## Environment Variables

See `.env.example` for all configuration options. Key variables:

- `DATABASE_URL` — PostgreSQL connection string (`postgresql+asyncpg://user:pass@host:5432/dbname`)
- `SECRET_KEY` — JWT/session secret
- `NVD_API_KEY` — NVD API key (optional, increases rate limits)
- `LLM_ENABLED` — Enable AI-generated remediation text
- `ML_RETRAIN_ON_STARTUP` — Auto-train model on startup

## License

Proprietary — All rights reserved.
