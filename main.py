#!/usr/bin/env python3
"""
B-XSSRF v7 — End-to-End Automated Penetration Testing & Security Auditing Framework
for Android Applications and Backend Infrastructure.

Author: Mazen El-Gammal
License: MIT
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

# Setup logging FIRST before any other imports
from logging_setup import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)

# Silence noisy loggers
logging.getLogger("androguard").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("nmap").setLevel(logging.WARNING)

# Now import rich and other modules
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from attack_orchestrator import run_attacks
from config_loader import get_general_config, load_config
from core_engine import run_full_pipeline
from executor import check_adb
from payload_factory import generate_payloads
from reporter import create_report
from scraper import run as run_scraper
from server_scanner import run_server_module
from unpacker import decompile_apk

console = Console()


def clear_screen() -> None:
    """Clear terminal screen."""
    os.system("cls" if os.name == "nt" else "clear")


def show_header() -> None:
    """Display the B-XSSRF banner with hacker aesthetic."""
    banner = r"""
⠀⠀⠀⠀⠀⣠⣴⣶⣿⣿⠿⣷⣶⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣶⣷⠿⣿⣿⣶⣦⣀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣶⣦⣬⡉⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠚⢉⣥⣴⣾⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀
⠀⠀⠀⡾⠿⠛⠛⠛⠛⠿⢿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⣿⣿⣿⣿⣿⠿⠿⠛⠛⠛⠛⠿⢧⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⡿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣠⣤⠶⠶⠶⠰⠦⣤⣀⠀⠙⣷⠀⠀⠀⠀⠀⠀⠀⠀⢠⡿⠋⢀⣀⣤⢴⠆⠲⠶⠶⣤⣄⠀⠀⠀⠀⠀⠀
⠀⠘⣆⠀⠀⢠⣾⣫⣶⣾⣿⣿⣿⣿⣷⣯⣿⣦⠈⠃⡇⠀⠀⠀⠀⠀⢸⠘⢁⣶⣿⣵⣾⣿⣿⣿⣿⣷⣦⣝⣷⡄⠀⠀⡰⠂⠀
⠀⠀⣨⣷⣶⣿⣧⣛⣛⠿⠿⣿⢿⣿⣿⣛⣿⡿⠀⠀⡇⠀⠀⠀⠀⠀⢸⠀⠈⢿⣟⣛⠿⢿⡿⢿⢿⣛⣫⣼⡿⣶⣾⣅⡀⠀
⢀⡼⠋⠁⠀⠀⠀⠈⠉⠛⠛⠻⠟⠸⠛⠋⠉⠁⠀⠀⢸⡇⠀⠀⠄⠀⢸⡄⠀⠀⠈⠉⠙⠛⠃⠻⠛⠛⠛⠉⠁⠀⠀⠈⠙⢧⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⡇⢠⠀⠀⠀⢸⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⡇⠀⠀⠀⠀⢸⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠟⠁⣿⠇⠀⠀⠀⠀⢸⡇⠙⢿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠰⣄⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⠖⡾⠁⠀⠀⣿⠀⠀⠀⠀⠀⠘⣿⠀⠀⠙⡇⢸⣷⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠄⠀
⠀⠀⢻⣷⡦⣤⣤⣤⡴⠶⠿⠛⠉⠁⠀⢳⠀⢠⡀⢿⣀⠀⠀⠀⠀⣠⡟⢀⣀⢠⠇⠀⠈⠙⠛⠷⠶⢦⣤⣤⣤⢴⣾⡏⠀⠀
⠀⠀⠈⣿⣧⠙⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⢊⣙⠛⠒⠒⢛⣋⡚⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⡿⠁⣾⡿⠀⠀⠀
⠀⠀⠀⠘⣿⣇⠈⢿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⡿⢿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⡟⠁⣼⡿⠁⠀⠀⠀
⠀⠀⠀⠀⠘⣿⣦⠀⠻⣿⣷⣦⣤⣤⣶⣶⣶⣿⣿⣿⣿⠏⠀⠀⠻⣿⣿⣿⣿⣶⣶⣶⣦⣤⣴⣿⣿⠏⢀⣼⡿⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠘⢿⣷⣄⠙⠻⠿⠿⠿⠿⠿⢿⣿⣿⣿⣁⣀⣀⣀⣀⣙⣿⣿⣿⠿⠿⠿⠿⠿⠿⠟⠁⣠⣿⡿⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠻⣯⠙⢦⣀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⣠⠴⢋⣾⠟⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠙⢧⡀⠈⠉⠒⠀⠀⠀⠀⠀⠀⣀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠐⠒⠉⠁⢀⡾⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⣠⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢦⡀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⡇⠀⠀⠀⠀⠀⠀⢀⡴⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

    tagline = r"""
    ╔══════════════════════════════════════════════════════════════╗
    ║  B-XSSRF v7  │  End-to-End Automated Penetration Testing     ║
    ║  Android & Backend Infrastructure Security Auditing Framework ║
    ╚══════════════════════════════════════════════════════════════╝
"""

    config = get_general_config()

    # Print banner with matrix green style
    console.print(f"[bold bright_green]{banner}[/bold bright_green]")
    console.print(f"[bold bright_green]{tagline}[/bold bright_green]")
    console.print(f"[dim green]  Author: Mazen El-Gammal  │  GitHub: @mazen-elgammal10[/dim green]")
    console.print(f"[dim green]  Mode: INTERACTIVE  │  Target: {config.output_dir}[/dim green]\n")


def show_menu() -> None:
    """Display the main menu with hacker aesthetic."""
    from rich.columns import Columns
    from rich.text import Text

    menu_items = [
        ("[1]", "MOBILE AUDIT", "Static manifest analysis + secret extraction", "bright_cyan"),
        ("[2]", "INFRASTRUCTURE", "Network recon, port scanning, vuln assessment", "bright_blue"),
        ("[3]", "ATTACK CHAIN", "Build & execute exploit chains from findings", "bright_magenta"),
        ("[4]", "AUTO EXPLOIT", "Full automation: static → dynamic → exploit → report", "bright_red"),
        ("[5]", "DECOMPILE APK", "Decompile APK with apktool for manual analysis", "bright_green"),
        ("[6]", "GENERATE PAYLOADS", "Create custom exploitation payloads for endpoints", "bright_yellow"),
        ("[0]", "EXIT", "Terminate framework", "dim"),
    ]

    console.print("\n[bold bright_green]┌─[ MODULES ]─[/bold bright_green]\n")

    for num, name, desc, color in menu_items:
        num_text = Text(f"  {num}", style=f"bold {color}")
        name_text = Text(f" {name:<18}", style=f"bold {color}")
        desc_text = Text(f" → {desc}", style=f"dim {color}")
        console.print(f"{num_text}{name_text}{desc_text}")

    console.print("\n[bold bright_green]└─[ SELECT OPTION ]─[/bold bright_green]")


def validate_apk_path(apk_path: str) -> Path | None:
    """Validate and return Path object for APK."""
    path = Path(apk_path).expanduser().resolve()
    if not path.exists():
        console.print(f"[bold red][!] File not found: {path}[/bold red]")
        return None
    if path.suffix.lower() != ".apk":
        console.print("[bold yellow][!] Warning: File doesn't have .apk extension[/bold yellow]")
    return path


def mobile_audit() -> None:
    """Option 1: Mobile Audit - Static Analysis only."""
    apk_path = console.input("\n[bold bright_green]┌─[b-xssrf][/bold bright_green]\n[bold bright_green]└──►[/bold bright_green] [white]Enter APK Path:[/white] ")
    path = validate_apk_path(apk_path)
    if not path:
        return

    console.print("\n[bright_green][*][/bright_green] [white]Initializing Static Analysis Module...[/white]\n")

    results, sensitive = run_full_pipeline(str(path))

    # Display results table
    table = Table(title="STATIC ANALYSIS REPORT")
    table.add_column("Category")
    table.add_column("Parameter")
    table.add_column("Value")
    table.add_column("Risk")

    for row in results:
        table.add_row(*[str(x) for x in row])

    # Sensitive data
    risk_levels = {"URLs": "INFO", "Emails": "LOW", "API Keys": "HIGH", "Tokens": "CRITICAL"}
    for key in ["URLs", "Emails", "API Keys", "Tokens"]:
        values = sensitive.get(key, [])
        found = bool(values)
        value = ", ".join(values) if found else "Not Found"
        risk = risk_levels.get(key, "INFO") if found else "N/A"
        table.add_row("Secrets/APIs", key, value, risk)

    console.print(table)

    # Attack Chains
    console.print("\n[bold magenta]=== ATTACK CHAINS ===[/bold magenta]\n")

    chain_found = False
    for category, param, value, risk in results:
        if param == "Debuggable" and str(value).lower() == "true":
            console.print("[cyan]SCENARIO[/cyan] Debuggable ➜ JDWP ➜ Code Execution")
            chain_found = True
        if param == "AllowBackup" and str(value).lower() == "true":
            console.print("[cyan]SCENARIO[/cyan] Backup ➜ adb backup ➜ Data Extraction")
            chain_found = True
        if param.startswith("Exported Provider:") and "no permission" in str(value).lower():
            console.print(f"[cyan]SCENARIO[/cyan] {param} ➜ SQLi/Path Traversal")
            chain_found = True
        if param.startswith(("Exported Activity:", "Exported Service:", "Exported Receiver:")):
            if "no permission" in str(value).lower():
                console.print(f"[cyan]SCENARIO[/cyan] {param} ➜ Intent Injection")
                chain_found = True
        if param == "UsesCleartextTraffic" and str(value).lower() == "true":
            console.print("[cyan]SCENARIO[/cyan] Cleartext Traffic ➜ MITM")
            chain_found = True

    if not chain_found:
        console.print("[green][+] No obvious attack chains from current Manifest.[/green]")

    input("\n[Press Enter to return]")


def infrastructure_audit() -> None:
    """Option 2: Infrastructure Audit."""
    console.print("\n[bold cyan][*] Launching Infrastructure Recon Module...[/bold cyan]\n")

    try:
        run_server_module()
    except ImportError as e:
        console.print(f"[bold red][!] Module error: {e}[/bold red]")
        console.print("[yellow]Install dependencies: pip install python-nmap requests[/yellow]")
    except Exception as e:
        console.print(f"[bold red][!] Infrastructure module error: {e}[/bold red]")

    input("\n[Press Enter to return]")


def attack_chain() -> None:
    """Option 3: Attack Chain - Build and execute attack chains."""
    apk_path = console.input("\n[bold bright_green]┌─[b-xssrf][/bold bright_green]\n[bold bright_green]└──►[/bold bright_green] [white]Enter APK Path:[/white] ")
    path = validate_apk_path(apk_path)
    if not path:
        return

    console.print("\n[cyan][*] Running Static Analysis to build attack chain...[/cyan]\n")
    results, _ = run_full_pipeline(str(path))

    console.print("\n[bold magenta]=== ATTACK CHAINS ===[/bold magenta]\n")

    chain_found = False
    for category, param, value, risk in results:
        if param == "Debuggable" and str(value).lower() == "true":
            console.print("[cyan]SCENARIO[/cyan] Debuggable ➜ JDWP ➜ Code Execution")
            chain_found = True
        if param == "AllowBackup" and str(value).lower() == "true":
            console.print("[cyan]SCENARIO[/cyan] Backup ➜ adb backup ➜ Data Extraction")
            chain_found = True
        if param.startswith("Exported Provider:") and "no permission" in str(value).lower():
            console.print(f"[cyan]SCENARIO[/cyan] {param} ➜ SQLi/Path Traversal")
            chain_found = True
        if param.startswith(("Exported Activity:", "Exported Service:", "Exported Receiver:")):
            if "no permission" in str(value).lower():
                console.print(f"[cyan]SCENARIO[/cyan] {param} ➜ Intent Injection")
                chain_found = True
        if param == "UsesCleartextTraffic" and str(value).lower() == "true":
            console.print("[cyan]SCENARIO[/cyan] Cleartext Traffic ➜ MITM")
            chain_found = True

    if not chain_found:
        console.print("[green][+] لا توجد attack chains واضحة من الـ Manifest الحالي.[/green]")

    # Check ADB and execute if device connected
    if not check_adb():
        console.print("\n[yellow][!] مفيش جهاز متوصل عبر ADB — العرض ده نظري بس (مش منفذ فعليًا).[/yellow]")
        input("\n[Press Enter to return]")
        return

    console.print("\n[cyan][*] جهاز ADB متوصل — جاري تنفيذ الـ chain فعليًا...[/cyan]\n")
    findings = run_attacks(results)

    if not findings:
        console.print("[green][+] مفيش نتائج فعلية اتفعّلت من الأجهزة.[/green]")
    else:
        table = Table(title="ATTACK CHAIN FINDINGS")
        table.add_column("Type")
        table.add_column("Severity")
        table.add_column("Evidence")

        for f in findings:
            evidence = f.get("evidence")
            if isinstance(evidence, list):
                evidence = ", ".join(evidence)
            table.add_row(f.get("type", "unknown").upper(), f.get("severity", "UNKNOWN"), str(evidence))

        console.print(table)

    input("\n[Press Enter to return]")


def auto_exploit() -> None:
    """Option 4: Full Automation Chain."""
    apk_path = console.input("\n[bold bright_green]┌─[b-xssrf][/bold bright_green]\n[bold bright_green]└──►[/bold bright_green] [white]Enter APK Path:[/white] ")
    path = validate_apk_path(apk_path)
    if not path:
        return

    console.print("\n[bold red][*] AUTO EXPLOIT — Full Automation Chain[/bold red]\n")

    # 1) Static Analysis
    console.print("[cyan][1/5][/cyan] Static analysis...")
    results, sensitive = run_full_pipeline(str(path))

    table = Table(title="STATIC ANALYSIS REPORT")
    table.add_column("Category")
    table.add_column("Parameter")
    table.add_column("Value")
    table.add_column("Risk")

    for row in results:
        table.add_row(*[str(x) for x in row])

    risk_levels = {"URLs": "INFO", "Emails": "LOW", "API Keys": "HIGH", "Tokens": "CRITICAL"}
    for key in ["URLs", "Emails", "API Keys", "Tokens"]:
        values = sensitive.get(key, [])
        found = bool(values)
        value = ", ".join(values) if found else "Not Found"
        risk = risk_levels.get(key, "INFO") if found else "N/A"
        table.add_row("Secrets/APIs", key, value, risk)

    console.print(table)

    # 2) Decompile + Deep Secret Scan
    console.print("\n[cyan][2/5][/cyan] Decompiling APK for deep secrets scan...")
    extracted_dir = decompile_apk(str(path))
    scraped: dict[str, list[Any]] = {"secrets": [], "endpoints": [], "injection": []}

    if extracted_dir:
        scraped = run_scraper(extracted_dir)
        console.print(
            f"[green][+][/green] Endpoints found: {len(scraped['endpoints'])} | "
            f"Secrets found: {len(scraped['secrets'])} | "
            f"Injection patterns: {len(scraped['injection'])}"
        )
    else:
        console.print("[yellow][!] Decompilation failed (apktool installed?) — skipping deep scan.[/yellow]")

    # 3) Payload Generation
    console.print("\n[cyan][3/5][/cyan] Generating exploitation payloads...")
    all_payloads = []
    for endpoint in scraped.get("endpoints", [])[:5]:
        all_payloads.extend(generate_payloads(endpoint))

    if all_payloads:
        console.print(f"[green][+][/green] {len(all_payloads)} payloads generated from discovered endpoints.")
    else:
        console.print("[yellow][!] No endpoints found to generate payloads from.[/yellow]")

    # 4) Live Exploitation (if device connected)
    console.print("\n[cyan][4/5][/cyan] Checking for connected device / live exploitation...")
    findings = []
    if check_adb():
        findings = run_attacks(results)
        if findings:
            console.print(f"[green][+][/green] {len(findings)} live findings triggered.")
        else:
            console.print("[green][+][/green] No live findings triggered.")
    else:
        console.print("[yellow][!] No ADB device — skipping live exploitation phase.[/yellow]")

    # 5) Final Report
    console.print("\n[cyan][5/5][/cyan] Generating final report...")
    create_report(
        analysis_results=results,
        sensitive=sensitive,
        scraped=scraped,
        payloads=all_payloads,
        findings=findings,
        network_data=None,
        apk_path=str(path),
    )

    input("\n[Press Enter to return]")


def decompile_apk_menu() -> None:
    """Option 5: Decompile APK only."""
    apk_path = console.input("\n[bold bright_green]┌─[b-xssrf][/bold bright_green]\n[bold bright_green]└──►[/bold bright_green] [white]Enter APK Path:[/white] ")
    path = validate_apk_path(apk_path)
    if not path:
        return

    console.print("\n[cyan][*] Decompiling APK...[/cyan]\n")
    extracted = decompile_apk(str(path))

    if extracted:
        console.print(f"[green][+][/green] Decompiled to: [bold]{extracted}[/bold]")
    else:
        console.print("[red][!] Decompilation failed.[/red]")

    input("\n[Press Enter to return]")


def generate_payloads_menu() -> None:
    """Option 6: Generate payloads for a URL."""
    url = console.input("\n[bold green][+] Enter Base URL (e.g., https://example.com/api): [/bold green]")

    if not url.startswith(("http://", "https://")):
        console.print("[yellow][!] URL should start with http:// or https://[/yellow]")
        url = "https://" + url

    console.print("\n[cyan][*] Generating payloads...[/cyan]\n")
    payloads = generate_payloads(url)

    table = Table(title=f"GENERATED PAYLOADS ({len(payloads)} total)")
    table.add_column("#", style="cyan", width=4)
    table.add_column("Payload", style="white")

    for i, p in enumerate(payloads[:20], 1):
        table.add_row(str(i), p)

    if len(payloads) > 20:
        table.add_row("...", f"[dim]and {len(payloads) - 20} more[/dim]")

    console.print(table)

    # Offer to save
    save = console.input("\nSave payloads to file? (y/n): ").lower()
    if save == "y":
        filename = console.input("Filename: ") or "payloads.txt"
        Path(filename).write_text("\n".join(payloads), encoding="utf-8")
        console.print(f"[green][+] Saved to {filename}[/green]")

    input("\n[Press Enter to return]")


def main() -> None:
    """Main entry point."""
    # Load configuration
    try:
        load_config()
        logger.info("b-xssrf_started", version="7.0.0")
    except Exception as e:
        logger.warning("config_load_failed", error=str(e))

    while True:
        clear_screen()
        show_header()
        show_menu()

        choice = console.input("\n[bold]Select Option: [/bold]").strip()

        if choice == "1":
            mobile_audit()
        elif choice == "2":
            infrastructure_audit()
        elif choice == "3":
            attack_chain()
        elif choice == "4":
            auto_exploit()
        elif choice == "5":
            decompile_apk_menu()
        elif choice == "6":
            generate_payloads_menu()
        elif choice == "0":
            console.print("\n[bold yellow][*] Exiting B-XSSRF... Bye! 👋[/bold yellow]\n")
            break
        else:
            console.print("\n[bold red][!] Invalid option, try again.[/bold red]")
            input("\n[Press Enter to continue]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow][*] Interrupted by user. Goodbye![/bold yellow]")
        sys.exit(0)
    except Exception as e:
        logger.error("fatal_error", error=str(e), exc_info=True)
        console.print(f"\n[bold red][!] Fatal error: {e}[/bold red]")
        sys.exit(1)
