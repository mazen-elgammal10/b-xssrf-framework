"""
ADB Executor for B-XSSRF v7.
Handles device communication, app installation, and payload delivery.
"""

from __future__ import annotations

import subprocess
import time

from config_loader import get_exploitation_config
from logging_setup import get_logger, log_operation

logger = get_logger(__name__)


def send_payload_to_adb(uri_payload: str, wait_time: int = 2) -> tuple[bool, str]:
    """
    Send a Deep Link / Intent to the app on the device via ADB.

    Args:
        uri_payload: The URI/Intent payload to send
        wait_time: Seconds to wait after sending

    Returns:
        Tuple of (success, output)
    """
    config = get_exploitation_config()

    with log_operation("adb_send_payload", payload=uri_payload[:100]):
        try:
            command = [
                "adb", "shell", "am", "start",
                "-a", "android.intent.action.VIEW",
                "-d", uri_payload
            ]

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=config.adb.timeout
            )

            # Wait for app to process
            time.sleep(wait_time)

            stderr = result.stderr.lower()

            # Detect crash / failure
            if "error" in stderr or "exception" in stderr:
                logger.warning("adb_payload_failed", stderr=result.stderr[:200])
                return False, result.stderr

            logger.debug("adb_payload_sent", stdout=result.stdout[:200])
            return True, result.stdout

        except subprocess.TimeoutExpired:
            logger.error("adb_command_timeout", payload=uri_payload[:100])
            return False, "ADB command timed out"
        except Exception as e:
            logger.error("adb_command_error", error=str(e), exc_info=True)
            return False, str(e)


def check_adb() -> bool:
    """
    Check if ADB is running and a device is connected.

    Returns:
        True if device connected, False otherwise
    """
    config = get_exploitation_config()

    try:
        result = subprocess.run(
            ["adb", "devices"],
            capture_output=True,
            text=True,
            timeout=config.adb.timeout
        )

        # Check for device in output (not just "List of devices attached")
        lines = result.stdout.strip().split("\n")
        for line in lines[1:]:  # Skip header
            if line.strip() and "\tdevice" in line:
                logger.debug("adb_device_found", device_line=line.strip())
                return True

        logger.debug("no_adb_device_connected")
        return False

    except Exception as e:
        logger.error("adb_check_failed", error=str(e))
        return False


def install_apk(apk_path: str) -> tuple[bool, str]:
    """
    Install APK on connected device.

    Args:
        apk_path: Path to APK file

    Returns:
        Tuple of (success, output)
    """
    config = get_exploitation_config()

    with log_operation("adb_install_apk", apk_path=apk_path):
        try:
            result = subprocess.run(
                ["adb", "install", "-r", apk_path],
                capture_output=True,
                text=True,
                timeout=config.adb.timeout * 3  # Install can take longer
            )

            success = "success" in result.stdout.lower()
            if success:
                logger.info("apk_installed", apk_path=apk_path)
            else:
                logger.warning("apk_install_failed", stderr=result.stderr[:200])

            return success, result.stdout if success else result.stderr

        except subprocess.TimeoutExpired:
            logger.error("apk_install_timeout", apk_path=apk_path)
            return False, "APK install timed out"
        except Exception as e:
            logger.error("apk_install_error", error=str(e), exc_info=True)
            return False, str(e)


def launch_app(package_name: str) -> bool:
    """
    Launch app on device.

    Args:
        package_name: Package name to launch

    Returns:
        True if launch command succeeded
    """
    with log_operation("adb_launch_app", package_name=package_name):
        try:
            subprocess.run(
                ["adb", "shell", "monkey", "-p", package_name,
                 "-c", "android.intent.category.LAUNCHER", "1"],
                capture_output=True,
                text=True,
                timeout=10
            )
            logger.debug("app_launch_command_sent", package_name=package_name)
            return True
        except Exception as e:
            logger.error("app_launch_failed", package_name=package_name, error=str(e))
            return False


def get_package_name(apk_path: str) -> str | None:
    """
    Extract package name from APK using aapt.

    Args:
        apk_path: Path to APK file

    Returns:
        Package name or None if failed
    """
    try:
        result = subprocess.run(
            ["aapt", "dump", "badging", apk_path],
            capture_output=True,
            text=True,
            timeout=10
        )

        for line in result.stdout.split("\n"):
            if line.startswith("package: name="):
                # package: name='com.example' versionCode='1' versionName='1.0'
                import re
                match = re.search(r"name='([^']+)'", line)
                if match:
                    return match.group(1)

    except Exception as e:
        logger.debug("package_name_extraction_failed", error=str(e))

    return None


def pull_file(remote_path: str, local_path: str) -> tuple[bool, str]:
    """
    Pull a file from device.

    Args:
        remote_path: Path on device
        local_path: Local destination path

    Returns:
        Tuple of (success, output)
    """
    config = get_exploitation_config()

    with log_operation("adb_pull_file", remote=remote_path, local=local_path):
        try:
            result = subprocess.run(
                ["adb", "pull", remote_path, local_path],
                capture_output=True,
                text=True,
                timeout=config.adb.timeout * 2
            )

            success = result.returncode == 0
            return success, result.stdout if success else result.stderr

        except Exception as e:
            logger.error("adb_pull_failed", error=str(e))
            return False, str(e)


def run_shell_command(command: str, timeout: int | None = None) -> tuple[bool, str]:
    """
    Run arbitrary shell command on device.

    Args:
        command: Shell command to run
        timeout: Command timeout in seconds

    Returns:
        Tuple of (success, output)
    """
    config = get_exploitation_config()

    with log_operation("adb_shell_command", command=command[:100]):
        try:
            result = subprocess.run(
                ["adb", "shell", command],
                capture_output=True,
                text=True,
                timeout=timeout or config.adb.timeout
            )

            return result.returncode == 0, result.stdout

        except subprocess.TimeoutExpired:
            logger.error("adb_shell_timeout", command=command[:100])
            return False, "Command timed out"
        except Exception as e:
            logger.error("adb_shell_error", error=str(e))
            return False, str(e)
