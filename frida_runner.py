"""
Frida Runner for B-XSSRF v7.
Manages Frida-based dynamic analysis.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from config_loader import get_dynamic_analysis_config
from logging_setup import get_logger, log_operation

logger = get_logger(__name__)


def run_frida(package_name: str, script_path: str | None = None, extra_scripts: list[str] | None = None) -> bool:
    """
    Run Frida against a target package.

    Args:
        package_name: Target package name
        script_path: Main Frida script path
        extra_scripts: Additional script paths to load

    Returns:
        True if Frida started successfully
    """
    config = get_dynamic_analysis_config()

    with log_operation("run_frida", package_name=package_name):
        # Determine script path
        if script_path is None:
            script_path = config.script_path

        script_file = Path(script_path)
        if not script_file.exists():
            logger.error("frida_script_not_found", path=script_path)
            return False

        # Build command
        cmd = ["frida"]

        if config.spawn_mode:
            cmd.extend(["-f", package_name])
        else:
            cmd.extend(["-U", "-n", package_name])

        cmd.extend(["-l", str(script_file), "--no-pause"])

        # Add extra scripts
        for extra in (extra_scripts or config.additional_scripts):
            extra_path = Path(extra)
            if extra_path.exists():
                cmd.extend(["-l", str(extra_path)])
            else:
                logger.warning("frida_extra_script_not_found", path=extra)

        logger.info("frida_command", cmd=" ".join(cmd))

        try:
            # Run Frida (blocking)
            subprocess.run(cmd, check=True)
            return True

        except subprocess.CalledProcessError as e:
            logger.error("frida_exited_with_error", returncode=e.returncode)
            return False
        except KeyboardInterrupt:
            logger.info("frida_interrupted")
            return True
        except FileNotFoundError:
            logger.error("frida_not_installed")
            return False
        except Exception as e:
            logger.error("frida_failed", error=str(e), exc_info=True)
            return False


def run_frida_script(
    package_name: str,
    script_content: str,
    timeout: int = 30,
) -> tuple[bool, str]:
    """
    Run a Frida script directly from string content.

    Args:
        package_name: Target package
        script_content: Frida JavaScript code
        timeout: Execution timeout in seconds

    Returns:
        Tuple of (success, output)
    """
    import tempfile

    with log_operation("run_frida_script", package_name=package_name):
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
                f.write(script_content)
                script_path = f.name

            cmd = ["frida", "-U", "-f", package_name, "-l", script_path, "--no-pause"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            # Cleanup
            Path(script_path).unlink(missing_ok=True)

            return result.returncode == 0, result.stdout

        except subprocess.TimeoutExpired:
            return False, "Frida script timed out"
        except Exception as e:
            return False, str(e)


def list_frida_processes() -> list[dict[str, Any]]:
    """List processes visible to Frida on connected device."""
    try:
        result = subprocess.run(
            ["frida-ps", "-U"],
            capture_output=True,
            text=True,
            timeout=10
        )

        processes = []
        for line in result.stdout.strip().split("\n")[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 2:
                processes.append({
                    "pid": parts[0],
                    "name": " ".join(parts[1:]),
                })
        return processes

    except Exception as e:
        logger.error("frida_ps_failed", error=str(e))
        return []


def check_frida_device() -> bool:
    """Check if Frida server is running on device."""
    try:
        result = subprocess.run(
            ["frida-ps", "-U"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False
