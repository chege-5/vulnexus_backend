# VulNexus — AI-Based Cryptography Vulnerability Scanner (Backend)

Hybrid AI-powered backend system that scans source code and live websites for cryptographic vulnerabilities, scores them using machine learning, maps them to real CVEs, and generates professional audit reports.

## Architecture

```
User Input → Static Code Scanner → Web TLS Scanner → Rule Engine
    → Feature Engineering → AI Risk Scoring → CVE Mapping
    → Audit Report Generator → API Response
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| API Framework | FastAPI (async) |
| Database | PostgreSQL 16 + SQLAlchemy 2.0 |
| Migrations | Alembic |
| ML | scikit-learn (Random Forest + Isolation Forest) |
| Reports | WeasyPrint (PDF) / Jinja2 (HTML) |
| Performance | Rust via PyO3 (optional) |
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

### 3. Run migrations

```bash
docker-compose exec backend alembic upgrade head
```

### 4. Train ML model

```bash
docker-compose exec backend python scripts/train_model.py
```

### 5. Access API

- API: http://localhost:8000
- Docs: http://localhost:8000/docs
- Health: http://localhost:8000/healthz
- Metrics: http://localhost:8000/metrics

## Local Development

```bash
python -m venv venv
venv\Scripts\activate      # Windows
pip install -r requirements.txt

# Start PostgreSQL locally, then:
alembic upgrade head
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
│   ├── deps.py                 # Database session factory
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
├── rust_modules/
│   ├── Cargo.toml
│   ├── build.rs
│   └── src/
│       ├── lib.rs              # PyO3 Python bindings
│       └── crypto_analysis.rs  # Entropy, ZIP parsing, pattern detection
├── tests/
│   ├── test_file_scanner.py
│   ├── test_web_scanner.py
│   ├── test_ai_model.py
│   └── test_integration.py
├── alembic/
│   ├── env.py
│   └── versions/
│       └── 001_initial_schema.py
├── scripts/
│   ├── train_model.py
│   └── init_db.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── alembic.ini
└── .env.example
```

## Scanning Capabilities

### Static Code Scanner
- Hardcoded keys and secrets
- Weak hash algorithms (MD5, SHA-1)
- Weak ciphers (DES, RC2, AES-ECB)
- Insecure random number generators
- Small RSA keys (< 2048 bits)
- Small AES keys (< 128 bits)
- Private key detection

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

## ML Model

- **Primary**: Random Forest Classifier (4 severity classes)
- **Optional**: Isolation Forest (anomaly detection)
- **Features**: 16 cryptographic security indicators
- **Output**: Risk score (0-100) + severity classification
- **Persistence**: joblib serialization

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

## Environment Variables

See `.env.example` for all configuration options. Key variables:

- `DATABASE_URL` — PostgreSQL connection string
- `SECRET_KEY` — JWT/session secret
- `NVD_API_KEY` — NVD API key (optional, increases rate limits)
- `LLM_ENABLED` — Enable AI-generated remediation text
- `ML_RETRAIN_ON_STARTUP` — Auto-train model on startup

## Building Rust Module (Optional)

```bash
cd rust_modules
pip install maturin
maturin develop --release
```

## License

Proprietary — All rights reserved.
