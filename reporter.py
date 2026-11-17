"""
Advanced Reporter for B-XSSRF v7.
Generates comprehensive security reports in multiple formats (Console, TXT, JSON, SARIF, HTML).
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from config_loader import get_reporting_config, get_risk_scoring_config
from logging_setup import get_logger, log_operation

console = Console()
logger = get_logger(__name__)


# ============================
# Internal Formatters
# ============================

def _fmt_manifest_risks(analysis_results: list[list[str]] | None) -> str:
    """Format manifest risks for report."""
    if not analysis_results:
        return "No manifest analysis data available."

    risky = []
    for row in analysis_results:
        if len(row) < 4:
            continue
        category, param, value, risk = row[0], row[1], row[2], row[3]
        if category == "Manifest" and str(value).lower() == "true":
            risky.append(f"{param} = true ({risk})")

    if not risky:
        return "No risky manifest flags detected."

    return "\n".join(risky)


def _fmt_secrets(sensitive: dict[str, list[str]] | None) -> str:
    """Format secrets from manifest scan."""
    if not sensitive:
        return "No sensitive data extracted."

    lines = []
    for key in ["URLs", "Emails", "API Keys", "Tokens"]:
        values = sensitive.get(key, [])
        if values:
            lines.append(f"{key}: {', '.join(values)}")

    return "\n".join(lines) if lines else "No sensitive data found."


def _fmt_scraped(scraped: dict[str, list[Any]] | None) -> str:
    """Format deep scan results."""
    if not scraped:
        return "Deep scan was not performed."

    secrets = scraped.get("secrets", [])
    endpoints = scraped.get("endpoints", [])
    injections = scraped.get("injection", [])

    lines = [
        f"Secrets found: {len(secrets)}",
        f"Endpoints found: {len(endpoints)}",
        f"Injection patterns found: {len(injections)}",
    ]

    if endpoints:
        lines.append("Sample endpoints:")
        for e in endpoints[:5]:
            lines.append(f"  - {e}")

    if secrets:
        lines.append("Sample secrets:")
        for s in secrets[:5]:
            lines.append(f"  - {s}")

    if injections:
        lines.append("Sample injection patterns:")
        for i in injections[:3]:
            lines.append(f"  - {i}")

    return "\n".join(lines)


def _fmt_payloads(payloads: list[str] | None) -> str:
    """Format generated payloads."""
    if not payloads:
        return "No payloads were generated (no endpoints discovered)."

    lines = [f"Total payloads generated: {len(payloads)}"]
    lines.append("Sample:")
    for p in payloads[:5]:
        lines.append(f"  - {p}")

    return "\n".join(lines)


def _fmt_findings(findings: list[dict[str, Any]] | None) -> str:
    """Format live exploitation findings."""
    if not findings:
        return "No live findings triggered (no device connected or nothing exploitable)."

    lines = []
    for f in findings:
        evidence = f.get("evidence")
        if isinstance(evidence, list):
            evidence = ", ".join(evidence) if evidence else "N/A"
        severity = f.get("severity", "UNKNOWN")
        lines.append(f"[{severity}] {f.get('type', 'unknown').upper()}: {evidence}")

    return "\n".join(lines)


def _fmt_network(network_data: dict[str, Any] | None) -> str:
    """Format network/infrastructure scan results."""
    if not network_data:
        return "Infrastructure scan was not performed in this run."

    target = network_data.get("target", "N/A")
    ports = network_data.get("ports", [])
    ssrf = network_data.get("ssrf", False)
    rce = network_data.get("rce", False)

    lines = [
        f"Target: {target}",
        f"Open Ports: {', '.join(str(p) for p in ports) if ports else 'None found'}",
        f"SSRF Vulnerable: {'YES' if ssrf else 'No'}",
        f"RCE Vulnerable: {'YES' if rce else 'No'}",
    ]

    return "\n".join(lines)


def _build_recommendations(
    analysis_results: list[list[str]] | None,
    sensitive: dict[str, list[str]] | None,
    scraped: dict[str, list[Any]] | None,
    findings: list[dict[str, Any]] | None,
    network_data: dict[str, Any] | None,
) -> str:
    """Build dynamic recommendations based on actual findings."""
    recs = []
    risk_config = get_risk_scoring_config()

    # Manifest-based recommendations
    for row in (analysis_results or []):
        if len(row) < 4:
            continue
        category, param, value, risk = row[0], row[1], row[2], row[3]

        if param == "Debuggable" and str(value).lower() == "true":
            recs.append("Disable android:debuggable in production builds.")
        if param == "AllowBackup" and str(value).lower() == "true":
            recs.append('Set android:allowBackup="false" to prevent data extraction via adb backup.')
        if param == "UsesCleartextTraffic" and str(value).lower() == "true":
            recs.append("Disable android:usesCleartextTraffic; enforce HTTPS via Network Security Config.")
        if param == "NetworkSecurityConfig" and str(value).lower() == "missing":
            recs.append("Add a Network Security Config (res/xml/network_security_config.xml) to enforce TLS.")
        if param.startswith("Exported Provider:") and "no permission" in str(value).lower():
            recs.append("Restrict exported Content Provider with android:permission or set android:exported=\"false\".")
        if param.startswith(("Exported Activity:", "Exported Service:", "Exported Receiver:")) and "no permission" in str(value).lower():
            recs.append("Add permission protection to exported component or set android:exported=\"false\".")
        if param == "BackupAgent" and str(value).lower() != "none":
            recs.append("Review custom BackupAgent implementation for data leakage.")
        if param == "ExtractNativeLibs" and str(value).lower() == "true":
            recs.append("Set android:extractNativeLibs=\"false\" to prevent native library extraction.")

    # Sensitive data recommendations
    if sensitive and any(sensitive.get(k) for k in ["API Keys", "Tokens"]):
        recs.append("Remove hardcoded API keys/tokens from the app; move them to a secure backend with proper rotation.")

    # Deep scan recommendations
    if scraped and scraped.get("secrets"):
        recs.append("Rotate and remove secrets found in decompiled source (smali/resources).")
    if scraped and scraped.get("injection"):
        recs.append("Review code for SQL injection, path traversal, and deserialization vulnerabilities found in deep scan.")

    # Live exploitation recommendations
    if findings:
        recs.append("Live exploitation succeeded — patch the underlying vulnerabilities before release.")

    # Network recommendations
    if network_data and (network_data.get("ssrf") or network_data.get("rce")):
        recs.append("Close/firewall the affected network ports and patch the vulnerable service.")

    # Default
    if not recs:
        recs.append("No critical issues detected in this run — keep monitoring and re-test regularly.")

    return "\n".join(f"- {r}" for r in recs)


# ============================
# SARIF Generation
# ============================

def _generate_sarif(
    analysis_results: list[list[str]] | None,
    sensitive: dict[str, list[str]] | None,
    scraped: dict[str, list[Any]] | None,
    payloads: list[str] | None,
    findings: list[dict[str, Any]] | None,
    network_data: dict[str, Any] | None,
    apk_path: str | None = None,
) -> dict[str, Any]:
    """Generate SARIF 2.1.0 report."""
    reporting_config = get_reporting_config()
    sarif_config = reporting_config.sarif

    results: list[dict[str, Any]] = []
    rule_map: dict[str, dict[str, Any]] = {}

    def add_rule(rule_id: str, name: str, description: str, severity: str) -> None:
        if rule_id not in rule_map:
            rule_map[rule_id] = {
                "id": rule_id,
                "name": name,
                "shortDescription": {"text": description},
                "fullDescription": {"text": description},
                "defaultConfiguration": {"level": _severity_to_sarif_level(severity)},
                "help": {"text": description, "markdown": description},
            }

    def add_result(rule_id: str, message: str, locations: list[dict[str, Any]] | None = None, level: str | None = None) -> None:
        result = {
            "ruleId": rule_id,
            "message": {"text": message},
        }
        if locations:
            result["locations"] = locations
        if level:
            result["level"] = level
        results.append(result)

    def _severity_to_sarif_level(severity: str) -> str:
        mapping = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note",
        }
        return mapping.get(severity.upper(), "warning")

    # Manifest risks
    if analysis_results:
        for row in analysis_results:
            if len(row) < 4:
                continue
            category, param, value, risk = row[0], row[1], row[2], row[3]
            if category == "Manifest" and str(value).lower() == "true":
                rule_id = f"manifest-{param.lower().replace(' ', '-')}"
                add_rule(rule_id, f"Manifest: {param}", f"Insecure manifest setting: {param} = {value}", risk)
                add_result(rule_id, f"{param} is set to {value} ({risk})", level=_severity_to_sarif_level(risk))

    # Sensitive data
    if sensitive:
        for key in ["API Keys", "Tokens"]:
            values = sensitive.get(key, [])
            for val in values:
                rule_id = f"secret-{key.lower().replace(' ', '-')}"
                add_rule(rule_id, f"Hardcoded {key}", f"Hardcoded {key} found in APK", key)
                add_result(rule_id, f"Hardcoded {key}: {val[:50]}...", level=_severity_to_sarif_level(key))

    # Deep scan findings
    if scraped:
        for secret in scraped.get("secrets", []):
            rule_id = "secret-deep-scan"
            add_rule(rule_id, "Secret in Decompiled Code", "Sensitive data found in decompiled source", "HIGH")
            add_result(rule_id, f"Secret found: {secret[:100]}", level="warning")

        for endpoint in scraped.get("endpoints", []):
            rule_id = "endpoint-discovery"
            add_rule(rule_id, "Endpoint Discovered", "Potential attack surface endpoint found", "INFO")
            add_result(rule_id, f"Endpoint: {endpoint}", level="note")

    # Live findings
    if findings:
        for finding in findings:
            rule_id = f"exploit-{finding.get('type', 'unknown')}"
            severity = finding.get("severity", "MEDIUM")
            add_rule(rule_id, f"Live Exploitation: {finding.get('type')}", finding.get("evidence", "Exploited"), severity)
            add_result(rule_id, finding.get("evidence", "Vulnerability exploited"), level=_severity_to_sarif_level(severity))

    # Network findings
    if network_data:
        if network_data.get("ssrf"):
            rule_id = "network-ssrf"
            add_rule(rule_id, "Server-Side Request Forgery", "SSRF vulnerability detected on infrastructure", "HIGH")
            add_result(rule_id, f"SSRF vulnerable on {network_data.get('target')}", level="error")
        if network_data.get("rce"):
            rule_id = "network-rce"
            add_rule(rule_id, "Remote Code Execution", "RCE vulnerability detected on infrastructure", "CRITICAL")
            add_result(rule_id, f"RCE vulnerable on {network_data.get('target')}", level="error")

    # Build SARIF
    return {
        "version": sarif_config.get("version", "2.1.0"),
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": sarif_config.get("tool_name", "B-XSSRF"),
                    "version": sarif_config.get("tool_version", "7.0.0"),
                    "informationUri": "https://github.com/mazen-elgammal10/b-xssrf-framework",
                    "rules": list(rule_map.values()),
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.utcnow().isoformat() + "Z",
                "toolExecutionArguments": [apk_path] if apk_path else [],
            }],
        }]
    }


# ============================
# JSON Generation
# ============================

def _generate_json(
    analysis_results: list[list[str]] | None,
    sensitive: dict[str, list[str]] | None,
    scraped: dict[str, list[Any]] | None,
    payloads: list[str] | None,
    findings: list[dict[str, Any]] | None,
    network_data: dict[str, Any] | None,
    apk_path: str | None = None,
) -> dict[str, Any]:
    """Generate structured JSON report."""
    return {
        "metadata": {
            "tool": "B-XSSRF",
            "version": "7.0.0",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "apk_path": apk_path,
        },
        "manifest_analysis": analysis_results or [],
        "sensitive_data": sensitive or {},
        "deep_scan": scraped or {},
        "generated_payloads": payloads or [],
        "live_findings": findings or [],
        "network_scan": network_data or {},
        "recommendations": _build_recommendations(
            analysis_results, sensitive, scraped, findings, network_data
        ).split("\n"),
    }


# ============================
# Main Report Generation
# ============================

def create_report(
    analysis_results: list[list[str]] | None = None,
    sensitive: dict[str, list[str]] | None = None,
    scraped: dict[str, list[Any]] | None = None,
    payloads: list[str] | None = None,
    findings: list[dict[str, Any]] | None = None,
    network_data: dict[str, Any] | None = None,
    apk_path: str | None = None,
) -> dict[str, str]:
    """
    Generate comprehensive security report in multiple formats.

    Returns:
        Dict mapping format -> report content (or file path for saved reports)
    """
    reporting_config = get_reporting_config()
    formats = reporting_config.formats
    sections = reporting_config.sections

    with log_operation("generate_report", formats=formats):
        reports: dict[str, str] = {}

        # 1. Console Report (Rich Table)
        if "console" in formats:
            _print_console_report(
                analysis_results, sensitive, scraped, payloads, findings, network_data, sections
            )
            reports["console"] = "printed"

        # 2. Text Report
        if "txt" in formats:
            txt_content = _generate_text_report(
                analysis_results, sensitive, scraped, payloads, findings, network_data, apk_path
            )
            reports["txt"] = txt_content

        # 3. JSON Report
        if "json" in formats:
            json_data = _generate_json(
                analysis_results, sensitive, scraped, payloads, findings, network_data, apk_path
            )
            reports["json"] = json.dumps(json_data, indent=2, ensure_ascii=False)

        # 4. SARIF Report
        if "sarif" in formats:
            sarif_data = _generate_sarif(
                analysis_results, sensitive, scraped, payloads, findings, network_data, apk_path
            )
            reports["sarif"] = json.dumps(sarif_data, indent=2, ensure_ascii=False)

        # 5. HTML Report (placeholder for future)
        if "html" in formats:
            reports["html"] = _generate_html_report(
                analysis_results, sensitive, scraped, payloads, findings, network_data, apk_path
            )

        # Auto-save if enabled
        if reporting_config.auto_save:
            _auto_save_reports(reports, reporting_config)

        # Prompt user to save
        _prompt_save_reports(reports, reporting_config)

        logger.info("report_generation_complete", formats=list(reports.keys()))
        return reports


def _print_console_report(
    analysis_results: list[list[str]] | None,
    sensitive: dict[str, list[str]] | None,
    scraped: dict[str, list[Any]] | None,
    payloads: list[str] | None,
    findings: list[dict[str, Any]] | None,
    network_data: dict[str, Any] | None,
    sections: list[str],
) -> None:
    """Print rich console report."""
    console.print("\n[bold yellow][*] Generating Advanced Security Report...[/bold yellow]")

    table = Table(title="[bold red]DETAILED VULNERABILITY REPORT[/bold red]", border_style="red")
    table.add_column("Phase", style="cyan", no_wrap=True)
    table.add_column("Key Findings & Data", style="white")

    section_map = {
        "manifest_risks": ("1. Manifest Risks", _fmt_manifest_risks(analysis_results)),
        "secrets_manifest": ("2. Secrets (Manifest scan)", _fmt_secrets(sensitive)),
        "deep_scan": ("3. Deep Scan (Decompiled)", _fmt_scraped(scraped)),
        "generated_payloads": ("4. Generated Payloads", _fmt_payloads(payloads)),
        "live_exploitation": ("5. Live Exploitation", _fmt_findings(findings)),
        "network_infra": ("6. Network/Infra Scan", _fmt_network(network_data)),
        "recommendations": ("7. Recommendation", f"[bold yellow]{_build_recommendations(analysis_results, sensitive, scraped, findings, network_data)}[/bold yellow]"),
    }

    for section in sections:
        if section in section_map:
            title, content = section_map[section]
            table.add_row(title, content)

    console.print(table)


def _generate_text_report(
    analysis_results: list[list[str]] | None,
    sensitive: dict[str, list[str]] | None,
    scraped: dict[str, list[Any]] | None,
    payloads: list[str] | None,
    findings: list[dict[str, Any]] | None,
    network_data: dict[str, Any] | None,
    apk_path: str | None,
) -> str:
    """Generate text report."""
    lines = []
    lines.append("=" * 60)
    lines.append("       B-XSSRF v7 - PROFESSIONAL AUDIT REPORT")
    lines.append(f"       Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if apk_path:
        lines.append(f"       Target: {apk_path}")
    lines.append("=" * 60 + "\n")

    sections = [
        ("SECTION 1: MANIFEST RISKS", _fmt_manifest_risks(analysis_results)),
        ("SECTION 2: SECRETS (Manifest Scan)", _fmt_secrets(sensitive)),
        ("SECTION 3: DEEP SCAN (Decompiled Source)", _fmt_scraped(scraped)),
        ("SECTION 4: GENERATED PAYLOADS", _fmt_payloads(payloads)),
        ("SECTION 5: LIVE EXPLOITATION RESULTS", _fmt_findings(findings)),
        ("SECTION 6: NETWORK / INFRASTRUCTURE SCAN", _fmt_network(network_data)),
        ("SECTION 7: RECOMMENDATIONS", _build_recommendations(analysis_results, sensitive, scraped, findings, network_data)),
    ]

    for title, content in sections:
        lines.append(f"[+] {title}")
        lines.append("-" * 40)
        lines.append(content + "\n")

    lines.append("=" * 60)
    lines.append("       END OF REPORT - SECURE YOUR SYSTEM")
    lines.append("=" * 60)

    return "\n".join(lines)


def _generate_html_report(
    analysis_results: list[list[str]] | None,
    sensitive: dict[str, list[str]] | None,
    scraped: dict[str, list[Any]] | None,
    payloads: list[str] | None,
    findings: list[dict[str, Any]] | None,
    network_data: dict[str, Any] | None,
    apk_path: str | None,
) -> str:
    """Generate HTML report (basic implementation)."""
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>B-XSSRF v7 Security Report</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; max-width: 1000px; margin: 0 auto; padding: 20px; background: #f5f5f5; }}
        .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #c00; border-bottom: 2px solid #c00; padding-bottom: 10px; }}
        h2 {{ color: #333; border-left: 4px solid #c00; padding-left: 10px; }}
        .meta {{ color: #666; font-size: 0.9em; margin-bottom: 20px; }}
        pre {{ background: #f8f8f8; padding: 15px; border-radius: 4px; overflow-x: auto; }}
        .critical {{ color: #c00; font-weight: bold; }}
        .high {{ color: #e60; font-weight: bold; }}
        .medium {{ color: #c60; }}
        .low {{ color: #080; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; }}
        th {{ background: #f0f0f0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>B-XSSRF v7 - Security Audit Report</h1>
        <div class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        {f'<div class="meta">Target APK: {apk_path}</div>' if apk_path else ''}
"""

    sections = [
        ("Manifest Risks", _fmt_manifest_risks(analysis_results)),
        ("Secrets (Manifest Scan)", _fmt_secrets(sensitive)),
        ("Deep Scan (Decompiled)", _fmt_scraped(scraped)),
        ("Generated Payloads", _fmt_payloads(payloads)),
        ("Live Exploitation", _fmt_findings(findings)),
        ("Network/Infrastructure Scan", _fmt_network(network_data)),
        ("Recommendations", _build_recommendations(analysis_results, sensitive, scraped, findings, network_data)),
    ]

    for title, content in sections:
        html += f"<h2>{title}</h2><pre>{content}</pre>"

    html += """
    </div>
</body>
</html>"""
    return html


def _auto_save_reports(reports: dict[str, str], config: Any) -> None:
    """Auto-save reports to output directory."""
    from datetime import datetime

    output_dir = Path(config.filename_template).parent if "{" not in config.filename_template else Path("./output")
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    for fmt, content in reports.items():
        if fmt == "console":
            continue
        filename = config.filename_template.format(timestamp=timestamp, ext=fmt)
        filepath = output_dir / filename
        filepath.write_text(content, encoding="utf-8")
        logger.info("report_auto_saved", format=fmt, path=str(filepath))


def _prompt_save_reports(reports: dict[str, str], config: Any) -> None:
    """Prompt user to save reports manually."""
    if not reports or all(k == "console" for k in reports):
        return

    save_choice = input("\nDo you want to save this full report? (y/n): ").lower()
    if save_choice != 'y':
        return

    filename = input("Enter filename (e.g., report.txt): ") or "final_report.txt"

    # Save all formats with base filename
    base = Path(filename).stem
    output_dir = Path(filename).parent or Path(".")
    output_dir.mkdir(parents=True, exist_ok=True)

    for fmt, content in reports.items():
        if fmt == "console":
            continue
        ext = fmt if fmt != "sarif" else "sarif"
        out_path = output_dir / f"{base}.{ext}"
        out_path.write_text(content, encoding="utf-8")
        console.print(f"[bold green][+][/bold green] Report saved to: [bold white]{out_path}[/bold white]")
