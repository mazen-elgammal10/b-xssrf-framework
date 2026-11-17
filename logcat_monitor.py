"""
Logcat Monitor for B-XSSRF v7.
Collects and manages Android logcat output during exploitation.
"""

from __future__ import annotations

import subprocess
import time
from typing import Callable

from config_loader import get_exploitation_config
from logging_setup import get_logger, log_operation

logger = get_logger(__name__)


def clear_logcat() -> bool:
    """
    Clear the logcat buffer.

    Returns:
        True if successful
    """
    config = get_exploitation_config()

    with log_operation("clear_logcat"):
        try:
            subprocess.run(
                ["adb", "logcat", "-c"],
                capture_output=True,
                timeout=config.adb.timeout
            )
            logger.debug("logcat_cleared")
            return True
        except Exception as e:
            logger.error("clear_logcat_failed", error=str(e))
            return False


def collect_logs(duration: int = 3, filter_spec: str | None = None) -> str:
    """
    Collect logcat output for a specified duration.

    Args:
        duration: Seconds to collect logs
        filter_spec: Optional logcat filter (e.g., "*:E" for errors only)

    Returns:
        Collected logcat output as string
    """
    config = get_exploitation_config()

    with log_operation("collect_logcat", duration=duration):
        try:
            cmd = ["adb", "logcat", "-d"]
            if filter_spec:
                cmd.extend(["-s", filter_spec])

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            time.sleep(duration)

            output, stderr = process.communicate(timeout=5)

            if stderr:
                logger.debug("logcat_stderr", stderr=stderr[:200])

            logger.debug("logcat_collected", lines=len(output.splitlines()), chars=len(output))
            return output

        except subprocess.TimeoutExpired:
            logger.error("logcat_collection_timeout")
            return ""
        except Exception as e:
            logger.error("logcat_collection_failed", error=str(e))
            return ""


def collect_logs_since(timestamp: str, filter_spec: str | None = None) -> str:
    """
    Collect logcat output since a specific timestamp.

    Args:
        timestamp: ISO format timestamp or 'YYYY-MM-DD HH:MM:SS.mmm'
        filter_spec: Optional logcat filter

    Returns:
        Collected logcat output
    """
    config = get_exploitation_config()

    with log_operation("collect_logcat_since", timestamp=timestamp):
        try:
            cmd = ["adb", "logcat", "-T", timestamp]
            if filter_spec:
                cmd.extend(["-s", filter_spec])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.adb.timeout
            )

            return result.stdout

        except Exception as e:
            logger.error("logcat_collection_since_failed", error=str(e))
            return ""


def stream_logcat(
    callback: Callable[[str], None],
    filter_spec: str | None = None,
    duration: int | None = None,
) -> None:
    """
    Stream logcat in real-time, calling callback for each line.

    Args:
        callback: Function(line: str) -> None
        filter_spec: Optional logcat filter
        duration: Optional max duration in seconds
    """
    config = get_exploitation_config()

    with log_operation("stream_logcat", duration=duration):
        try:
            cmd = ["adb", "logcat"]
            if filter_spec:
                cmd.extend(["-s", filter_spec])

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            if process.stdout is None:
                return

            start_time = time.time()
            for line in iter(process.stdout.readline, ""):
                if duration and (time.time() - start_time) > duration:
                    break
                callback(line.rstrip())

            process.terminate()

        except Exception as e:
            logger.error("logcat_stream_failed", error=str(e))
