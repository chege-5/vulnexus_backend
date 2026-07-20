import os
import hmac
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from prometheus_client import make_asgi_app
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from redis import asyncio as redis_asyncio

from app.config import settings
from app.deps import close_db, init_db
from app.rate_limit import limiter
from app.routes import scan_routes, report_routes, dashboard_routes, auth_routes, admin_routes, notification_routes, vulnerability_routes, project_routes
from app.services.integrations import integration_manager
from app.utils.logger import get_logger

logger = get_logger(__name__)
cors_origins = [origin.strip() for origin in settings.CORS_ORIGINS.split(",") if origin.strip()]


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/metrics") and settings.METRICS_TOKEN:
            authorization = request.headers.get("authorization", "")
            expected = f"Bearer {settings.METRICS_TOKEN}"
            if not hmac.compare_digest(authorization, expected):
                return JSONResponse(status_code=403, content={"detail": "Metrics access is forbidden"})
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        if settings.IS_PRODUCTION:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    await init_db()
    if settings.ENABLE_PROVIDER_HEALTHCHECKS:
        await integration_manager.initialize()
    oauth_diagnostics = settings.safe_oauth_diagnostics()
    logger.info(
        "VulNexus backend starting up: environment=%s frontend_origin=%s backend_origin=%s "
        "google_callback=%s github_callback=%s redis_state_storage_enabled=%s",
        oauth_diagnostics["environment"], oauth_diagnostics["frontend_origin"], oauth_diagnostics["backend_origin"],
        oauth_diagnostics["google_callback_host_and_path"], oauth_diagnostics["github_callback_host_and_path"],
        oauth_diagnostics["redis_state_storage_enabled"],
    )
    yield
    await close_db()
    logger.info("VulNexus backend shutting down")


app = FastAPI(
    title="VulNexus - AI Cryptography Vulnerability Scanner",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(SQLAlchemyError)
async def database_error_handler(request: Request, exc: SQLAlchemyError):
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    # Do not stringify SQLAlchemy exceptions: their text can contain SQL
    # parameters such as tokens, emails, or password hashes.
    logger.error(
        "Database request failed request_id=%s method=%s path=%s error_type=%s",
        request_id,
        request.method,
        request.url.path,
        type(exc).__name__,
    )
    content = {"detail": "Database service is temporarily unavailable"}
    if not settings.IS_PRODUCTION:
        content["request_id"] = request_id
    return JSONResponse(status_code=503, content=content, headers={"X-Request-ID": request_id})

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
    expose_headers=["X-Access-Token"],
)
app.add_middleware(SecurityHeadersMiddleware)
# Railway terminates TLS at its proxy.  Trust the forwarded scheme so generated
# redirects and security decisions remain HTTPS-aware behind that proxy.
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

app.include_router(auth_routes.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(scan_routes.router, prefix="/api/v1", tags=["scans"])
app.include_router(report_routes.router, prefix="/api/v1", tags=["reports"])
app.include_router(dashboard_routes.router, prefix="/api/v1", tags=["dashboard"])
app.include_router(admin_routes.router, prefix="/api/v1", tags=["admin"])
app.include_router(notification_routes.router, prefix="/api/v1", tags=["notifications"])
app.include_router(vulnerability_routes.router, prefix="/api/v1", tags=["vulnerabilities"])
app.include_router(project_routes.router, prefix="/api/v1", tags=["projects"])

app.add_api_route(
    "/api/v1/subscribe-plan",
    auth_routes.subscribe_plan,
    methods=["POST"],
    tags=["auth"],
)

metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


@app.get("/healthz")
async def healthz():
    checks = {"database": False, "redis": False}
    try:
        from app.database import engine
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception:
        logger.exception("Health check database probe failed")

    redis_client = redis_asyncio.from_url(settings.REDIS_URL)
    try:
        await redis_client.ping()
        checks["redis"] = True
    except Exception:
        logger.exception("Health check Redis probe failed")
    finally:
        await redis_client.aclose()

    if settings.IS_PRODUCTION and not all(checks.values()):
        raise HTTPException(status_code=503, detail={"status": "unavailable", "checks": checks})
    return {"status": "ok", "checks": checks}
