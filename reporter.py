import os
from datetime import datetime

from rich.console import Console
from rich.table import Table

console = Console()


def _fmt_manifest_risks(analysis_results):
    """
    بيرجع بس السطور اللي فيها خطورة فعلية من نتايج الـ Manifest
    (Debuggable=true, AllowBackup=true) بدل ما نعرض كل حاجة.
    """
    if not analysis_results:
        return "No manifest analysis data available."

    risky = []
    for row in analysis_results:
        # row = [category, parameter, value, risk]
        if len(row) < 4:
            continue
        category, param, value, risk = row[0], row[1], row[2], row[3]
        if category == "Manifest" and str(value).lower() == "true":
            risky.append(f"{param} = true ({risk})")

    if not risky:
        return "No risky manifest flags detected."

    return "\n".join(risky)


def _fmt_secrets(sensitive):
    """
    بيرجع ملخص للـ secrets الحقيقية اللي طلعت من manifest_parser
    (URLs / Emails / API Keys / Tokens)
    """
    if not sensitive:
        return "No sensitive data extracted."

    lines = []
    for key in ["URLs", "Emails", "API Keys", "Tokens"]:
        values = sensitive.get(key, [])
        if values:
            lines.append(f"{key}: {', '.join(values)}")

    return "\n".join(lines) if lines else "No sensitive data found."


def _fmt_scraped(scraped):
    """
    بيرجع ملخص لنتايج الـ deep scan (scraper.py) بعد فك الـ APK
    """
    if not scraped:
        return "Deep scan was not performed."

    secrets = scraped.get("secrets", [])
    endpoints = scraped.get("endpoints", [])

    lines = [
        f"Secrets found: {len(secrets)}",
        f"Endpoints found: {len(endpoints)}",
    ]

    if endpoints:
        lines.append("Sample endpoints:")
        for e in endpoints[:3]:
            lines.append(f"  - {e}")

    if secrets:
        lines.append("Sample secrets:")
        for s in secrets[:3]:
            lines.append(f"  - {s}")

    return "\n".join(lines)


def _fmt_payloads(payloads):
    if not payloads:
        return "No payloads were generated (no endpoints discovered)."

    lines = [f"Total payloads generated: {len(payloads)}"]
    lines.append("Sample:")
    for p in payloads[:3]:
        lines.append(f"  - {p}")

    return "\n".join(lines)


def _fmt_findings(findings):
    if not findings:
        return "No live findings triggered (no device connected or nothing exploitable)."

    lines = []
    for f in findings:
        evidence = f.get("evidence")
        if isinstance(evidence, list):
            evidence = ", ".join(evidence) if evidence else "N/A"
        lines.append(f"{f.get('type', 'unknown').upper()}: {evidence}")

    return "\n".join(lines)


def _fmt_network(network_data):
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


def _build_recommendations(analysis_results, sensitive, scraped, findings, network_data):
    """
    توصيات مبنية فعليًا على النتايج اللي طلعت، مش نص ثابت
    """
    recs = []

    for row in (analysis_results or []):
        if len(row) < 4:
            continue
        category, param, value, risk = row[0], row[1], row[2], row[3]
        if param == "Debuggable" and str(value).lower() == "true":
            recs.append("Disable android:debuggable in production builds.")
        if param == "AllowBackup" and str(value).lower() == "true":
            recs.append("Set android:allowBackup=\"false\" to prevent data extraction via adb backup.")

    if sensitive and any(sensitive.get(k) for k in ["API Keys", "Tokens"]):
        recs.append("Remove hardcoded API keys/tokens from the app; move them to a secure backend.")

    if scraped and scraped.get("secrets"):
        recs.append("Rotate and remove secrets found in decompiled source (smali/resources).")

    if findings:
        recs.append("Live exploitation succeeded — patch the underlying vulnerabilities before release.")

    if network_data and (network_data.get("ssrf") or network_data.get("rce")):
        recs.append("Close/firewall the affected network ports and patch the vulnerable service.")

    if not recs:
        recs.append("No critical issues detected in this run — keep monitoring and re-test regularly.")

    return "\n".join(f"- {r}" for r in recs)


def create_report(analysis_results=None, sensitive=None, scraped=None,
                   payloads=None, findings=None, network_data=None):
    """
    analysis_results : list من manifest_parser.get_attack_surface() (نتايج Mobile Audit)
    sensitive        : dict من manifest_parser.extract_sensitive_data()
    scraped          : dict من scraper.run() (بعد فك الـ APK)
    payloads         : list من payload_factory.generate_payloads()
    findings         : list من attack_orchestrator.run_attacks() (live exploitation)
    network_data     : dict من server_scanner (target/ports/ssrf/rce) لو اتعمل infra scan
    """
    console.print("\n[bold yellow][*] Generating Advanced Security Report...[/bold yellow]")

    table = Table(title="[bold red]DETAILED VULNERABILITY REPORT[/bold red]", border_style="red")
    table.add_column("Phase", style="cyan", no_wrap=True)
    table.add_column("Key Findings & Data", style="white")

    table.add_row("1. Manifest Risks", _fmt_manifest_risks(analysis_results))
    table.add_row("2. Secrets (Manifest scan)", _fmt_secrets(sensitive))
    table.add_row("3. Deep Scan (Decompiled)", _fmt_scraped(scraped))
    table.add_row("4. Generated Payloads", _fmt_payloads(payloads))
    table.add_row("5. Live Exploitation", _fmt_findings(findings))
    table.add_row("6. Network/Infra Scan", _fmt_network(network_data))
    table.add_row(
        "7. Recommendation",
        f"[bold yellow]{_build_recommendations(analysis_results, sensitive, scraped, findings, network_data)}[/bold yellow]"
    )

    console.print(table)

    save_choice = input("\nDo you want to save this full report? (y/n): ").lower()

    if save_choice != 'y':
        return

    filename = input("Enter filename (e.g., report.txt): ") or "final_report.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("       B-XSSRF v7 - PROFESSIONAL AUDIT REPORT\n")
        f.write(f"       Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")

        f.write("[+] SECTION 1: MANIFEST RISKS\n")
        f.write("-" * 40 + "\n")
        f.write(_fmt_manifest_risks(analysis_results) + "\n\n")

        f.write("[+] SECTION 2: SECRETS (Manifest Scan)\n")
        f.write("-" * 40 + "\n")
        f.write(_fmt_secrets(sensitive) + "\n\n")

        f.write("[+] SECTION 3: DEEP SCAN (Decompiled Source)\n")
        f.write("-" * 40 + "\n")
        f.write(_fmt_scraped(scraped) + "\n\n")

        f.write("[+] SECTION 4: GENERATED PAYLOADS\n")
        f.write("-" * 40 + "\n")
        f.write(_fmt_payloads(payloads) + "\n\n")

        f.write("[+] SECTION 5: LIVE EXPLOITATION RESULTS\n")
        f.write("-" * 40 + "\n")
        f.write(_fmt_findings(findings) + "\n\n")

        f.write("[+] SECTION 6: NETWORK / INFRASTRUCTURE SCAN\n")
        f.write("-" * 40 + "\n")
        f.write(_fmt_network(network_data) + "\n\n")

        f.write("[+] SECTION 7: RECOMMENDATIONS\n")
        f.write("-" * 40 + "\n")
        f.write(_build_recommendations(analysis_results, sensitive, scraped, findings, network_data) + "\n")

        f.write("\n" + "=" * 60 + "\n")
        f.write("       END OF REPORT - SECURE YOUR SYSTEM\n")
        f.write("=" * 60 + "\n")

    console.print(f"[bold green][+][/bold green] Professional report saved to: [bold white]{filename}[/bold white]")
