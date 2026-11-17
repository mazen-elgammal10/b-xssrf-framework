"""
Structured logging setup for B-XSSRF v7 using structlog.
Replaces the crude logging.disable() approach with proper structured logging.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

import structlog
from structlog.types import EventDict, Processor

from config_loader import get_general_config

# ============================
# Custom Processors
# ============================

def add_timestamp(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Add ISO timestamp to log entries."""
    from datetime import datetime, timezone
    event_dict["timestamp"] = datetime.now(timezone.utc).isoformat()
    return event_dict


def add_level(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Add log level to event dict."""
    event_dict["level"] = method_name.upper()
    return event_dict


def filter_sensitive_data(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Filter out sensitive data from logs (API keys, tokens, passwords)."""
    sensitive_keys = {
        "api_key", "apikey", "password", "secret", "token",
        "authorization", "auth", "bearer", "access_token",
        "refresh_token", "private_key", "api_secret"
    }

    def _filter(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {
                k: "***" if k.lower() in sensitive_keys else _filter(v)
                for k, v in obj.items()
            }
        elif isinstance(obj, list):
            return [_filter(item) for item in obj]
        return obj

    return _filter(event_dict)


def drop_debug_logs(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Drop debug logs unless explicitly enabled."""
    config = get_general_config()
    if method_name == "debug" and config.log_level.upper() != "DEBUG":
        raise structlog.DropEvent
    return event_dict


# ============================
# Logging Configuration
# ============================

def configure_logging(
    log_level: str | None = None,
    json_output: bool = False,
    log_file: str | Path | None = None,
) -> None:
    """
    Configure structured logging for the application.

    Args:
        log_level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_output: Output logs as JSON (for log aggregation)
        log_file: Optional file path to write logs to
    """
    config = get_general_config()
    level = log_level or config.log_level

    # Standard library logging setup
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
    )

    # Silence noisy third-party loggers
    logging.getLogger("androguard").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("nmap").setLevel(logging.WARNING)

    # Structlog processors
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        add_timestamp,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        filter_sensitive_data,
    ]

    if json_output:
        # JSON output for production/log aggregation
        processors = shared_processors + [
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Human-readable console output
        processors = shared_processors + [
            structlog.dev.ConsoleRenderer(colors=True),
        ]

    # Add file handler if specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
        file_handler.setFormatter(logging.Formatter("%(message)s"))

        # Add file processor
        file_processors = shared_processors + [
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ]

        structlog.configure(
            processors=file_processors,
            wrapper_class=structlog.make_filtering_bound_logger(
                getattr(logging, level.upper(), logging.INFO)
            ),
            logger_factory=structlog.WriteLoggerFactory(file=file_handler.stream),
            cache_logger_on_first_use=True,
        )
        return

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        logger_factory=structlog.WriteLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.BoundLogger:
    """Get a structured logger instance."""
    return structlog.get_logger(name)


# ============================
# Context Managers for Structured Logging
# ============================

class LogContext:
    """Context manager for adding structured context to logs."""

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self._tokens: list[structlog.contextvars.BoundContextVars] = []

    def __enter__(self) -> LogContext:
        token = structlog.contextvars.bind_contextvars(**self.kwargs)
        self._tokens.append(token)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        for token in reversed(self._tokens):
            structlog.contextvars.unbind_contextvars(*self.kwargs.keys())


def log_operation(operation: str, **kwargs: Any) -> LogContext:
    """Create a log context for an operation."""
    return LogContext(operation=operation, **kwargs)


# ============================
# Legacy Compatibility
# ============================

def silence_androguard_logs() -> None:
    """Legacy function to silence androguard logs (kept for compatibility)."""
    logging.getLogger("androguard").setLevel(logging.CRITICAL)
    logging.getLogger("androguard.core.apk").setLevel(logging.CRITICAL)
    logging.getLogger("androguard.core.axml").setLevel(logging.CRITICAL)
    logging.getLogger("androguard.decompiler").setLevel(logging.CRITICAL)


# Initialize default logging on import
configure_logging()
