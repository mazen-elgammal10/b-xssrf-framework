"""
Deep Scanner for B-XSSRF v7.
Scans decompiled APK source code for secrets, endpoints, and injection patterns.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from config_loader import get_static_analysis_config
from logging_setup import get_logger, log_operation

logger = get_logger(__name__)


def run(extraction_dir: str | Path) -> dict[str, list[Any]]:
    """
    Run deep scan on decompiled APK directory.

    Args:
        extraction_dir: Path to decompiled APK directory

    Returns:
        Dict with secrets, endpoints, and injection findings
    """
    results: dict[str, list[Any]] = {
        "secrets": [],
        "endpoints": [],
        "injection": [],
    }

    extraction_path = Path(extraction_dir)
    if not extraction_path.exists():
        logger.warning("extraction_dir_not_found", path=str(extraction_path))
        return results

    config = get_static_analysis_config()

    with log_operation("deep_scan", extraction_dir=str(extraction_path)):
        # Load patterns from config
        patterns = _build_patterns(config)

        files_scanned = 0
        for root, _, files in os.walk(extraction_path):
            for file in files:
                if not _should_scan_file(file, config):
                    continue

                path = Path(root) / file
                try:
                    content = path.read_text(encoding="utf-8", errors="ignore")
                    if len(content) > config.deep_scan.max_file_size:
                        continue

                    _scan_content(content, path, patterns, results)
                    files_scanned += 1

                except Exception as e:
                    logger.debug("file_scan_failed", file=str(path), error=str(e))

        # Clean results
        _clean_results(results, config)

        logger.info("deep_scan_complete",
                    files_scanned=files_scanned,
                    secrets=len(results["secrets"]),
                    endpoints=len(results["endpoints"]),
                    injections=len(results["injection"]))

    return results


def _should_scan_file(filename: str, config: Any) -> bool:
    """Check if file should be scanned based on extension and exclude patterns."""
    if not filename.endswith(tuple(config.deep_scan.extensions)):
        return False

    for pattern in config.deep_scan.exclude_patterns:
        if _match_glob(filename, pattern):
            return False

    return True


def _match_glob(filename: str, pattern: str) -> bool:
    """Simple glob pattern matching."""
    import fnmatch
    return fnmatch.fnmatch(filename, pattern)


def _build_patterns(config: Any) -> dict[str, list[tuple[str, str]]]:
    """Build regex patterns from configuration."""
    # Base patterns (can be extended from config)
    base_patterns = {
        "secrets_assignment": [
            (r"(?i)\b(api[_-]?key|password|secret|token|apikey|firebase)\b\s*[:=]\s*['\"]([^'\"\n]{4,100})['\"]", "assignment"),
        ],
        "secrets_labeled": [
            (r"(?i)\b(api\s*key|password|secret|token|firebase|user\s*name)\b\s*:\s*([^\"\\\n]{2,80})", "labeled"),
        ],
        "endpoints": [
            (r"https?://[\w\.-]+", "url"),
        ],
        "sql": [
            (r"(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\s+", "sql"),
        ],
        "path_traversal": [
            (r"\.\./|\.\.\\", "path_traversal"),
        ],
        "xxe": [
            (r"<!DOCTYPE|<!ENTITY", "xxe"),
        ],
        "deserialization": [
            (r"ObjectInputStream|readObject|Serializable", "deserialization"),
        ],
    }

    # Add custom patterns from config
    for name, pattern in config.sensitive_patterns.custom.items():
        if name not in base_patterns:
            base_patterns[name] = []
        base_patterns[name].append((pattern, "custom"))

    return base_patterns


def _scan_content(
    content: str,
    filepath: Path,
    patterns: dict[str, list[tuple[str, str]]],
    results: dict[str, list[Any]],
) -> None:
    """Scan file content for patterns."""
    for category, pattern_list in patterns.items():
        for pattern, ptype in pattern_list:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                if not matches:
                    continue

                if category in ("secrets_assignment", "secrets_labeled"):
                    for match in matches:
                        if isinstance(match, tuple) and len(match) >= 2:
                            label, value = match[0], match[1]
                        else:
                            label, value = "unknown", str(match)

                        value = value.strip()
                        if value and not _is_false_positive(value):
                            results["secrets"].append(f"{label.strip()}: {value}")

                elif category == "endpoints":
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0] if match else ""
                        if match and not _is_false_positive(match):
                            results["endpoints"].append(match)

                elif category in ("sql", "path_traversal", "xxe", "deserialization"):
                    for match in matches:
                        if isinstance(match, tuple):
                            match = str(match)
                        results["injection"].append(f"{category.upper()} in {filepath.name}: {match[:100]}")

            except Exception as e:
                logger.debug("pattern_scan_failed", category=category, error=str(e))


def _is_false_positive(value: str) -> bool:
    """Filter out common false positives."""
    # Smali/Java artifacts
    smali_markers = (
        "invoke-", "iget-", "iput-", "move-result", "Landroid/", "Ljava/",
        ".method", ".line", ".locals", ".register", ".prologue", ".epilogue",
        "const-string", "const/4", "const/16", "const", "move ", "return-",
        "if-", "goto ", "aput-", "aget-", "new-instance", "check-cast",
        "instance-of", "array-length", "new-array", "filled-new-array",
        "throw ", "monitor-", "cmp", "add-", "sub-", "mul-", "div-",
        "rem-", "and-", "or-", "xor-", "shl-", "shr-", "ushr-", "neg-",
        "not-", "float", "double", "int ", "long ", "byte ", "char ",
        "short ", "boolean", "void ", "class ", "interface ", "enum ",
        "annotation ", "default ", "transient ", "volatile ", "native ",
        "synchronized ", "strictfp ", "abstract ", "final ", "static ",
        "public ", "private ", "protected ", "package ", "import ",
        "extends ", "implements ", "throws ", r"super\(", r"this\(",
    )

    value_lower = value.lower()
    return any(marker in value_lower for marker in smali_markers)


def _clean_results(results: dict[str, list[Any]], config: Any) -> None:
    """Clean and deduplicate results."""
    max_results = config.deep_scan.max_results_per_category

    # Deduplicate secrets
    if results["secrets"]:
        seen = set()
        clean_secrets = []
        for s in results["secrets"]:
            if s not in seen and not _is_false_positive(s):
                seen.add(s)
                clean_secrets.append(s)
        results["secrets"] = clean_secrets[:max_results]

    # Deduplicate endpoints
    if results["endpoints"]:
        results["endpoints"] = list(dict.fromkeys(results["endpoints"]))[:max_results]

    # Deduplicate injections
    if results["injection"]:
        results["injection"] = list(dict.fromkeys(results["injection"]))[:max_results]
