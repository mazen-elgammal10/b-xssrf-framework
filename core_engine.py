"""
Core Engine for B-XSSRF v7.
Orchestrates the full analysis pipeline: Static -> Deep Scan -> Dynamic.
"""

from __future__ import annotations

import logging

from manifest_parser import BxssrfMobileParser

# Dynamic Analysis (Frida)
try:
    from frida_runner import run_frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

from logging_setup import get_logger

logger = get_logger(__name__)

# Silence androguard noise at module level
logging.getLogger("androguard").setLevel(logging.CRITICAL)


def run_full_pipeline(
    apk_path: str,
    package_name: str | None = None,
) -> tuple[list[list[str]], dict[str, list[str]]]:
    """
    Full Analysis Pipeline:
    1. Static Analysis (Manifest + Sensitive Data)
    2. Dynamic Analysis (Frida) - optional

    Args:
        apk_path: Path to the APK file
        package_name: Package name for dynamic analysis (Frida)

    Returns:
        Tuple of (attack_surface_results, sensitive_data)
    """
    results: list[list[str]] = []
    sensitive_data: dict[str, list[str]] = {}

    # Static Analysis
    try:
        with log_operation("static_analysis", apk_path=apk_path):
            parser = BxssrfMobileParser(apk_path)

            # Attack Surface
            results = parser.get_attack_surface()
            logger.info("static_analysis_complete", findings_count=len(results))

            # Sensitive Data Extraction
            sensitive_data = parser.extract_sensitive_data()
            total_secrets = sum(len(v) for v in sensitive_data.values())
            logger.info("sensitive_data_extracted", total_secrets=total_secrets)

    except Exception as e:
        logger.error("static_analysis_failed", error=str(e), exc_info=True)

    # Dynamic Analysis (Frida)
    if package_name and FRIDA_AVAILABLE:
        try:
            with log_operation("dynamic_analysis", package_name=package_name):
                logger.info("starting_frida_analysis")
                run_frida(package_name)
        except Exception as e:
            logger.error("frida_analysis_failed", error=str(e), exc_info=True)
    elif package_name and not FRIDA_AVAILABLE:
        logger.warning("frida_not_available", package_name=package_name)

    return results, sensitive_data


# Import here to avoid circular imports
from logging_setup import log_operation
