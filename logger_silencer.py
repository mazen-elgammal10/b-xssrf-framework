"""
Legacy logger silencer - kept for backward compatibility.
Use logging_setup.configure_logging() for new code.
"""

import logging
import sys

from logging_setup import silence_androguard_logs


def silence_all() -> None:
    """
    Legacy function to silence all logging.
    Deprecated: Use logging_setup.configure_logging() instead.
    """
    # Prevent any logging (stdlib)
    logging.disable(logging.CRITICAL)

    # Clear handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    # Silence androguard loggers
    silence_androguard_logs()

    # Silence loguru if present
    try:
        from loguru import logger as loguru_logger
        loguru_logger.remove()
    except ImportError:
        pass
    except ValueError:
        pass

    # Flush stdout/stderr
    sys.stdout.flush()
    sys.stderr.flush()
