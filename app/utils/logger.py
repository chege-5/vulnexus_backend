import logging
import sys
import time
import traceback
from contextlib import contextmanager
from app.config import settings
from app.utils.redaction import redact_data, redact_log_message


class SecretRedactionFilter(logging.Filter):
    """Last-line defense for application and dependency log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
            record.msg = redact_log_message(message)
            record.args = ()
            if record.stack_info:
                record.stack_info = redact_log_message(record.stack_info)
            if record.exc_info:
                record.exc_text = redact_log_message("".join(traceback.format_exception(*record.exc_info)))
        except Exception:
            record.msg = "[REDACTED LOG MESSAGE]"
            record.args = ()
        return True


def _add_redaction_filter(target) -> None:
    if not any(isinstance(item, SecretRedactionFilter) for item in target.filters):
        target.addFilter(SecretRedactionFilter())


def configure_log_redaction(logger: logging.Logger | None = None) -> None:
    """Install redaction on app, HTTP, Celery, and their active handlers."""
    targets = [logger] if logger else []
    targets.extend(logging.getLogger(name) for name in ("", "app", "httpx", "httpcore", "celery", "kombu", "uvicorn"))
    for target in targets:
        if target is None:
            continue
        _add_redaction_filter(target)
        for handler in target.handlers:
            _add_redaction_filter(handler)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    configure_log_redaction(logger)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        fmt = logging.Formatter(
            '{"time":"%(asctime)s","level":"%(levelname)s","module":"%(name)s","message":"%(message)s"}'
        )
        handler.setFormatter(fmt)
        _add_redaction_filter(handler)
        logger.addHandler(handler)
    logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))
    return logger


@contextmanager
def timed_stage(logger: logging.Logger, stage_name: str):
    start = time.perf_counter()
    logger.info(f"Stage '{stage_name}' started")
    try:
        yield
    finally:
        elapsed = time.perf_counter() - start
        logger.info(f"Stage '{stage_name}' completed in {elapsed:.3f}s")
