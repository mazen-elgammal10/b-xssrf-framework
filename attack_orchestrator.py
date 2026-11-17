"""
Attack Orchestrator for B-XSSRF v7.
Decides and executes attack chains based on analysis results.
"""

from __future__ import annotations

from typing import Any

from executor import send_payload_to_adb
from logcat_monitor import collect_logs
from logging_setup import get_logger, log_operation
from payload_factory import generate_payloads
from result_analyzer import analyze_logcat

logger = get_logger(__name__)


def decide_attacks(results: list[list[str]]) -> list[tuple[str, Any]]:
    """
    Decide which attacks to execute based on static analysis results.

    Args:
        results: List of [category, parameter, value, risk] from manifest analysis

    Returns:
        List of (attack_type, attack_data) tuples
    """
    attacks: list[tuple[str, Any]] = []

    with log_operation("decide_attacks", findings_count=len(results)):
        for row in results:
            if len(row) < 4:
                continue
            category, param, value, risk = row[0], row[1], row[2], row[3]

            # Deep Links -> SSRF/Injection via deeplink
            if param == "Deep Links" and value != "None":
                attacks.append(("deeplink", value))

            # AllowBackup -> Data extraction via adb backup
            if param == "AllowBackup" and str(value).lower() == "true":
                attacks.append(("backup", None))

            # Debuggable -> JDWP code execution
            if param == "Debuggable" and str(value).lower() == "true":
                attacks.append(("jdwp", None))

            # Exported Content Provider -> SQLi/Path Traversal
            if param.startswith("Exported Provider:") and str(value).lower() == "true (no permission)":
                attacks.append(("content_provider", param))

            # Exported Activity/Service/Receiver -> Intent injection
            if param.startswith(("Exported Activity:", "Exported Service:", "Exported Receiver:")):
                if str(value).lower() == "true (no permission)":
                    attacks.append(("intent_injection", param))

            # Cleartext Traffic -> MITM
            if param == "UsesCleartextTraffic" and str(value).lower() == "true":
                attacks.append(("cleartext_mitm", None))

        logger.info("attacks_decided", attack_count=len(attacks), attacks=[a[0] for a in attacks])

    return attacks


def run_attacks(results: list[list[str]]) -> list[dict[str, Any]]:
    """
    Execute decided attacks against connected device.

    Args:
        results: Static analysis results

    Returns:
        List of findings with evidence
    """
    findings: list[dict[str, Any]] = []

    attacks = decide_attacks(results)

    with log_operation("run_attacks", attack_count=len(attacks)):
        for attack_type, data in attacks:

            if attack_type == "deeplink":
                findings.extend(_run_deeplink_attack(data))

            elif attack_type == "backup":
                findings.append({
                    "type": "backup",
                    "evidence": "App allows backup → possible data extraction via 'adb backup'",
                    "severity": "HIGH",
                })

            elif attack_type == "jdwp":
                findings.append({
                    "type": "jdwp",
                    "evidence": "App is debuggable → JDWP code execution possible (port 8700)",
                    "severity": "CRITICAL",
                })

            elif attack_type == "content_provider":
                findings.extend(_run_content_provider_attack(data))

            elif attack_type == "intent_injection":
                findings.extend(_run_intent_injection_attack(data))

            elif attack_type == "cleartext_mitm":
                findings.append({
                    "type": "cleartext_traffic",
                    "evidence": "App allows cleartext HTTP traffic → MITM possible",
                    "severity": "HIGH",
                })

    logger.info("attacks_completed", findings_count=len(findings))
    return findings


def _run_deeplink_attack(deeplinks: list[str] | str) -> list[dict[str, Any]]:
    """Execute deeplink-based attacks with payload injection."""
    findings: list[dict[str, Any]] = []

    links = deeplinks if isinstance(deeplinks, list) else [deeplinks]

    with log_operation("deeplink_attack", links=links):
        for link in links:
            payloads = generate_payloads(link)

            for payload in payloads:
                ok, _ = send_payload_to_adb(payload)

                if not ok:
                    continue

                # Collect and analyze logs
                logs = collect_logs()
                analysis = analyze_logcat(logs)

                if analysis:
                    findings.append({
                        "type": "deeplink",
                        "payload": payload,
                        "evidence": analysis,
                        "severity": "HIGH",
                    })
                    logger.warning("deeplink_vulnerability_found",
                                 payload=payload[:100],
                                 evidence=analysis)

    return findings


def _run_content_provider_attack(provider_info: str) -> list[dict[str, Any]]:
    """Test Content Provider for SQLi and Path Traversal."""
    findings: list[dict[str, Any]] = []

    # TODO: Implement actual Content Provider exploitation
    # This would use ContentResolver via ADB or a test app
    findings.append({
        "type": "content_provider",
        "target": provider_info,
        "evidence": "Exported Content Provider detected - manual SQLi/Path Traversal testing recommended",
        "severity": "HIGH",
    })

    return findings


def _run_intent_injection_attack(component_info: str) -> list[dict[str, Any]]:
    """Test exported components for Intent injection."""
    findings: list[dict[str, Any]] = []

    # TODO: Implement actual Intent injection testing
    findings.append({
        "type": "intent_injection",
        "target": component_info,
        "evidence": "Exported component detected - manual Intent injection testing recommended",
        "severity": "MEDIUM",
    })

    return findings
