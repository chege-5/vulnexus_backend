import logging
import sys
import time
from contextlib import contextmanager
from app.config import settings


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        fmt = logging.Formatter(
            '{"time":"%(asctime)s","level":"%(levelname)s","module":"%(name)s","message":"%(message)s"}'
        )
        handler.setFormatter(fmt)
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
