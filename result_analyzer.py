"""
Result Analyzer for B-XSSRF v7.
Analyzes logcat output for exploitation evidence.
"""

from __future__ import annotations

import re
from typing import Any

from logging_setup import get_logger, log_operation

logger = get_logger(__name__)


# Pre-compiled patterns for performance
PATTERNS = {
    "crash": [
        re.compile(r"FATAL EXCEPTION", re.IGNORECASE),
        re.compile(r"Exception.*:", re.IGNORECASE),
        re.compile(r"Error.*:", re.IGNORECASE),
        re.compile(r"Caused by:", re.IGNORECASE),
        re.compile(r"Stack trace:", re.IGNORECASE),
    ],
    "anr": [
        re.compile(r"ANR in", re.IGNORECASE),
        re.compile(r"Application Not Responding", re.IGNORECASE),
    ],
    "file_access": [
        re.compile(r"open failed: EACCES", re.IGNORECASE),
        re.compile(r"Permission denied", re.IGNORECASE),
        re.compile(r"FileNotFoundException", re.IGNORECASE),
        re.compile(r"SecurityException.*file", re.IGNORECASE),
    ],
    "webview": [
        re.compile(r"WebView.*http", re.IGNORECASE),
        re.compile(r"loadUrl.*http", re.IGNORECASE),
        re.compile(r"shouldOverrideUrlLoading", re.IGNORECASE),
        re.compile(r"onReceivedSslError", re.IGNORECASE),
        re.compile(r"JavaScript.*console", re.IGNORECASE),
    ],
    "intent": [
        re.compile(r"Intent.*start", re.IGNORECASE),
        re.compile(r"ActivityNotFoundException", re.IGNORECASE),
        re.compile(r"SecurityException.*Intent", re.IGNORECASE),
        re.compile(r"exported.*false", re.IGNORECASE),
    ],
    "sql": [
        re.compile(r"SQLiteException", re.IGNORECASE),
        re.compile(r"SQL.*syntax", re.IGNORECASE),
        re.compile(r"near.*syntax", re.IGNORECASE),
    ],
    "network": [
        re.compile(r"ConnectException", re.IGNORECASE),
        re.compile(r"SocketTimeoutException", re.IGNORECASE),
        re.compile(r"UnknownHostException", re.IGNORECASE),
        re.compile(r"SSLHandshakeException", re.IGNORECASE),
        re.compile(r"CertificateException", re.IGNORECASE),
    ],
    "jdwp": [
        re.compile(r"JDWP", re.IGNORECASE),
        re.compile(r"Debug.*port", re.IGNORECASE),
        re.compile(r"debugger", re.IGNORECASE),
    ],
    "backup": [
        re.compile(r"backup", re.IGNORECASE),
        re.compile(r"BackupAgent", re.IGNORECASE),
    ],
    "crypto": [
        re.compile(r"InvalidKeyException", re.IGNORECASE),
        re.compile(r"BadPaddingException", re.IGNORECASE),
        re.compile(r"IllegalBlockSizeException", re.IGNORECASE),
        re.compile(r"NoSuchAlgorithmException", re.IGNORECASE),
    ],
    "frida": [
        re.compile(r"Frida", re.IGNORECASE),
        re.compile(r"gum-js-loop", re.IGNORECASE),
        re.compile(r"LIBFRIDA", re.IGNORECASE),
    ],
}


def analyze_logcat(logs: str) -> list[str]:
    """
    Analyze logcat output for security-relevant events.

    Args:
        logs: Raw logcat output

    Returns:
        List of finding descriptions
    """
    if not logs:
        return []

    with log_operation("analyze_logcat", log_lines=len(logs.splitlines())):
        findings: list[str] = []
        logs_lower = logs.lower()

        # Check each pattern category
        for category, patterns in PATTERNS.items():
            matches = _find_patterns(logs, patterns)
            if matches:
                finding = _format_finding(category, matches[:3])  # Limit to 3 examples
                findings.append(finding)

        # Additional heuristic analysis
        findings.extend(_heuristic_analysis(logs))

        logger.info("logcat_analysis_complete", findings_count=len(findings))
        return findings


def _find_patterns(text: str, patterns: list[re.Pattern]) -> list[str]:
    """Find all matches for a list of patterns."""
    matches = []
    for pattern in patterns:
        for match in pattern.finditer(text):
            # Get context around match
            start = max(0, match.start() - 100)
            end = min(len(text), match.end() + 200)
            context = text[start:end].strip()
            matches.append(context)
    return matches


def _format_finding(category: str, matches: list[str]) -> str:
    """Format a finding from matches."""
    category_names = {
        "crash": "App Crash/Exception",
        "anr": "Application Not Responding (ANR)",
        "file_access": "File Access Violation",
        "webview": "WebView Activity",
        "intent": "Intent Handling Issue",
        "sql": "SQL Error/Injection Indicator",
        "network": "Network/SSL Issue",
        "jdwp": "JDWP/Debug Activity",
        "backup": "Backup Operation",
        "crypto": "Cryptographic Error",
        "frida": "Frida Detection",
    }

    name = category_names.get(category, category.title())
    examples = " | ".join(m[:150] for m in matches)
    return f"{name}: {examples}"


def _heuristic_analysis(logs: str) -> list[str]:
    """Additional heuristic analysis for exploitation indicators."""
    findings = []

    # Check for successful exploitation indicators
    success_indicators = [
        (r"uid=\d+", "Command Execution (uid found)"),
        (r"root@", "Root Shell Access"),
        (r"/data/data/.*shared_prefs", "Shared Preferences Access"),
        (r"/data/data/.*databases", "Database Access"),
        (r"javax\.crypto", "Crypto API Usage"),
        (r"SecretKeySpec", "Key Material in Logs"),
        (r"SharedPreferences.*getString", "Token/Secret Retrieval"),
        (r"okhttp.*Authorization", "Auth Header in Network Logs"),
    ]

    for pattern, description in success_indicators:
        if re.search(pattern, logs, re.IGNORECASE):
            findings.append(f"Exploitation Indicator - {description}")

    # Check for SSRF indicators
    ssrf_indicators = [
        r"169\.254\.169\.254",
        r"127\.0\.0\.1",
        r"localhost",
        r"metadata\.google\.internal",
        r"metadata\.azure\.com",
        r"169\.254\.169\.254",
    ]

    for pattern in ssrf_indicators:
        if re.search(pattern, logs, re.IGNORECASE):
            findings.append(f"SSRF Indicator - Internal metadata access attempted: {pattern}")
            break  # Only report once

    # Check for path traversal
    if re.search(r"\.\./|\.\.\\", logs):
        findings.append("Path Traversal Indicator - Directory traversal sequence in logs")

    return findings


def analyze_logcat_structured(logs: str) -> dict[str, Any]:
    """
    Analyze logcat and return structured results.

    Returns:
        Dict with categorized findings and metadata
    """
    if not logs:
        return {"findings": [], "stats": {}, "raw_matches": {}}

    findings = analyze_logcat(logs)

    # Count by category
    stats = {}
    for f in findings:
        category = f.split(":")[0] if ":" in f else "other"
        stats[category] = stats.get(category, 0) + 1

    return {
        "findings": findings,
        "stats": stats,
        "total_findings": len(findings),
        "log_lines": len(logs.splitlines()),
        "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
    }
