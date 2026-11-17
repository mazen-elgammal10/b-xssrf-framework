"""
APK Unpacker for B-XSSRF v7.
Handles APK decompilation using apktool.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from logging_setup import get_logger, log_operation

logger = get_logger(__name__)


def decompile_apk(apk_path: str | Path, output_dir: str | Path | None = None, force: bool = False) -> str | None:
    """
    Decompile APK using apktool.

    Args:
        apk_path: Path to APK file
        output_dir: Output directory (default: apk_path_extracted)
        force: Overwrite existing output directory

    Returns:
        Path to decompiled directory or None on failure
    """
    apk_path = Path(apk_path)
    if not apk_path.exists():
        logger.error("apk_not_found", path=str(apk_path))
        return None

    if output_dir is None:
        output_dir = apk_path.parent / f"{apk_path.stem}_extracted"
    else:
        output_dir = Path(output_dir)

    with log_operation("decompile_apk", apk=str(apk_path), output=str(output_dir)):
        # Handle existing directory
        if output_dir.exists():
            if force:
                logger.info("removing_existing_output", path=str(output_dir))
                shutil.rmtree(output_dir)
            else:
                logger.info("output_exists_skipping", path=str(output_dir))
                return str(output_dir)

        try:
            logger.info("starting_apktool_decompile")
            result = subprocess.run(
                ["apktool", "d", str(apk_path), "-o", str(output_dir), "-f"],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes for large APKs
            )

            if result.returncode == 0:
                logger.info("apk_decompiled", output_dir=str(output_dir))
                return str(output_dir)
            else:
                logger.error("apktool_failed", stderr=result.stderr[:500])
                return None

        except subprocess.TimeoutExpired:
            logger.error("apktool_timeout")
            return None
        except FileNotFoundError:
            logger.error("apktool_not_installed")
            return None
        except Exception as e:
            logger.error("decompile_failed", error=str(e), exc_info=True)
            return None


def recompile_apk(source_dir: str | Path, output_apk: str | Path, keystore: str | None = None) -> bool:
    """
    Recompile decompiled APK (for testing modifications).

    Args:
        source_dir: Decompiled APK directory
        output_apk: Output APK path
        keystore: Optional keystore for signing

    Returns:
        True if successful
    """
    source_dir = Path(source_dir)
    output_apk = Path(output_apk)

    with log_operation("recompile_apk", source=str(source_dir), output=str(output_apk)):
        try:
            cmd = ["apktool", "b", str(source_dir), "-o", str(output_apk)]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode != 0:
                logger.error("apktool_build_failed", stderr=result.stderr[:500])
                return False

            # Sign if keystore provided
            if keystore:
                return _sign_apk(output_apk, keystore)

            logger.info("apk_recompiled", output=str(output_apk))
            return True

        except Exception as e:
            logger.error("recompile_failed", error=str(e))
            return False


def _sign_apk(apk_path: Path, keystore: str) -> bool:
    """Sign APK with provided keystore."""
    # This would use apksigner or jarsigner
    # Implementation depends on keystore format
    logger.warning("apk_signing_not_implemented")
    return False


def run(apk_path: str | None = None) -> str | None:
    """
    CLI entry point for manual decompilation.

    Args:
        apk_path: APK path (prompts if not provided)

    Returns:
        Decompiled directory path or None
    """
    if apk_path is None:
        apk_path = input("Enter path to APK: ").strip()

    apk_path = Path(apk_path)
    if apk_path.exists():
        return decompile_apk(apk_path)
    else:
        logger.error("file_not_found", path=str(apk_path))
        return None


def get_apk_info(apk_path: str | Path) -> dict[str, Any]:
    """Get basic APK information using aapt."""
    apk_path = Path(apk_path)

    info: dict[str, Any] = {
        "package": None,
        "version_code": None,
        "version_name": None,
        "min_sdk": None,
        "target_sdk": None,
        "permissions": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
    }

    try:
        result = subprocess.run(
            ["aapt", "dump", "badging", str(apk_path)],
            capture_output=True,
            text=True,
            timeout=30
        )

        output = result.stdout
        import re

        # Package info
        pkg_match = re.search(r"package: name='([^']+)' versionCode='(\d+)' versionName='([^']+)'", output)
        if pkg_match:
            info["package"] = pkg_match.group(1)
            info["version_code"] = pkg_match.group(2)
            info["version_name"] = pkg_match.group(3)

        # SDK versions
        min_sdk = re.search(r"sdkVersion:'(\d+)'", output)
        if min_sdk:
            info["min_sdk"] = min_sdk.group(1)

        target_sdk = re.search(r"targetSdkVersion:'(\d+)'", output)
        if target_sdk:
            info["target_sdk"] = target_sdk.group(1)

        # Permissions
        info["permissions"] = re.findall(r"uses-permission: name='([^']+)'", output)

        # Components
        info["activities"] = re.findall(r"launchable-activity: name='([^']+)'", output)

    except Exception as e:
        logger.error("aapt_failed", error=str(e))

    return info
