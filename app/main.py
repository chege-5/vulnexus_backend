import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from prometheus_client import make_asgi_app

from app.config import settings
from app.deps import close_db, init_db
from app.rate_limit import limiter
from app.routes import scan_routes, report_routes, dashboard_routes, auth_routes, admin_routes, notification_routes, vulnerability_routes
from app.services.integrations import integration_manager
from app.utils.logger import get_logger

logger = get_logger(__name__)
cors_origins = [origin.strip() for origin in settings.CORS_ORIGINS.split(",") if origin.strip()]


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(settings.ML_MODEL_PATH) or "ml_models", exist_ok=True)
    await init_db()
    if settings.ENABLE_PROVIDER_HEALTHCHECKS:
        await integration_manager.initialize()
    logger.info("VulNexus backend starting up")
    if settings.ML_RETRAIN_ON_STARTUP:
        from app.services.ai_risk_model import AIRiskModel
        model = AIRiskModel()
        model.train_model()
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_routes.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(scan_routes.router, prefix="/api/v1", tags=["scans"])
app.include_router(report_routes.router, prefix="/api/v1", tags=["reports"])
app.include_router(dashboard_routes.router, prefix="/api/v1", tags=["dashboard"])
app.include_router(admin_routes.router, prefix="/api/v1", tags=["admin"])
app.include_router(notification_routes.router, prefix="/api/v1", tags=["notifications"])
app.include_router(vulnerability_routes.router, prefix="/api/v1", tags=["vulnerabilities"])

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
    return {"status": "ok"}
