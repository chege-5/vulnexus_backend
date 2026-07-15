"""Application package bootstrap."""

# Install filters as soon as any app module is imported.  Some AI and provider
# modules instantiate httpx clients directly, so waiting for FastAPI/Celery
# startup would leave unit scripts and one-off workers unprotected.
from app.utils.logger import configure_log_redaction

configure_log_redaction()
