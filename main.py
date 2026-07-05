import logging
logging.disable(logging.CRITICAL)

import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core_engine import run_full_pipeline
from executor import check_adb
from attack_orchestrator import run_attacks
from unpacker import decompile_apk
from scraper import run as run_scraper
from payload_factory import generate_payloads
from reporter import create_report

console = Console()


def clear_screen():
    os.system("clear")


def show_header():
    banner = r"""
 ____        __  ______ ____  ____  _____ 
| __ )       \ \/ / ___/ ___||  _ \|  ___|
|  _ \   ___  \  /\___ \___ \| |_) | |_   
| |_) | |___| /  \ ___) |__) |  _ <|  _|  
|____/       /_/\_\____/____/|_| \_\_|    
            
B-XSSRF v7
    """

    console.print(
        Panel(
            f"[bold red]{banner}[/bold red]\n[bold blue]User: Mazen[/bold blue]",
            border_style="blue"
        )
    )


def show_menu():
    grid = Table.grid(expand=True)
    grid.add_column()
    grid.add_column()

    grid.add_row(
        Panel("[1] MOBILE AUDIT", border_style="cyan"),
        Panel("[2] INFRASTRUCTURE", border_style="white")
    )

    grid.add_row(
        Panel("[3] ATTACK CHAIN", border_style="magenta"),
        Panel("[4] AUTO EXPLOIT", border_style="red")
    )

    grid.add_row(
        Panel("[0] EXIT", border_style="yellow"),
        Panel("", border_style="black")
    )

    console.print(grid)


def mobile_audit():
    apk_path = console.input("\n[bold green][+] Enter APK Path: [/bold green]")

    console.print("\n[cyan][*] Running Static Analysis...[/cyan]\n")

    results, sensitive = run_full_pipeline(apk_path)

    # =============================
    # TABLE
    # =============================
    table = Table(title="STATIC ANALYSIS REPORT")

    table.add_column("Category")
    table.add_column("Parameter")
    table.add_column("Value")
    table.add_column("Risk")

    # Attack Surface
    for row in results:
        table.add_row(*[str(x) for x in row])

    # Sensitive Data
    for key in ["URLs", "Emails", "API Keys", "Tokens"]:
        values = sensitive.get(key, [])

        found = bool(values)
        value = ", ".join(values) if found else "Not Found"

        if not found:
            # لو الباراميتر مش موجود، مفيش خطورة أصلاً
            risk = "N/A"
        else:
            risk = "INFO"
            if key == "Emails":
                risk = "LOW"
            elif key == "API Keys":
                risk = "HIGH"
            elif key == "Tokens":
                risk = "CRITICAL"

        table.add_row("Secrets/APIs", key, value, risk)

    console.print(table)

    # =============================
    # ATTACK CHAINS
    # =============================
    console.print("\n[bold magenta]=== ATTACK CHAINS ===[/bold magenta]\n")

    console.print("[cyan]SCENARIO #1[/cyan]")
    console.print("Debuggable ➜ JDWP ➜ Code Execution\n")

    console.print("[cyan]SCENARIO #2[/cyan]")
    console.print("Backup ➜ adb backup ➜ Data Extraction\n")

    input("\n[Press Enter to return]")


def infrastructure_audit():
    """
    فحص البنية التحتية: بورتات مفتوحة + اختبار SSRF/RCE سريع
    (بيستخدم server_scanner.py الموجود عندك)
    """
    console.print("\n[bold cyan][*] Launching Infrastructure Recon Module...[/bold cyan]\n")

    try:
        import server_scanner
    except ImportError as e:
        console.print(f"[bold red][!] Module error: {e}[/bold red]")
        console.print("[yellow]تأكد إن مكتبة python-nmap و nmap متثبتين (pip install python-nmap).[/yellow]")
        input("\n[Press Enter to return]")
        return

    try:
        server_scanner.run_server_module()
    except Exception as e:
        console.print(f"[bold red][!] Infrastructure module error: {e}[/bold red]")

    input("\n[Press Enter to return]")


def attack_chain():
    """
    بيبني الـ attack chain من نتائج التحليل الثابت، ولو فيه جهاز
    متوصل عبر ADB بينفذ الهجمات فعليًا (backup / jdwp / deep links)
    """
    apk_path = console.input("\n[bold green][+] Enter APK Path: [/bold green]")

    console.print("\n[cyan][*] Running Static Analysis to build attack chain...[/cyan]\n")
    results, _ = run_full_pipeline(apk_path)

    console.print("\n[bold magenta]=== ATTACK CHAINS ===[/bold magenta]\n")

    chain_found = False
    for category, param, value, risk in results:
        if param == "Debuggable" and value == "true":
            console.print("[cyan]SCENARIO[/cyan] Debuggable ➜ JDWP ➜ Code Execution")
            chain_found = True
        if param == "AllowBackup" and value == "true":
            console.print("[cyan]SCENARIO[/cyan] Backup ➜ adb backup ➜ Data Extraction")
            chain_found = True

    if not chain_found:
        console.print("[green][+] لا توجد attack chains واضحة من الـ Manifest الحالي.[/green]")

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
        table.add_column("Evidence")

        for f in findings:
            evidence = f.get("evidence")
            if isinstance(evidence, list):
                evidence = ", ".join(evidence)
            table.add_row(f["type"], str(evidence))

        console.print(table)

    input("\n[Press Enter to return]")


def auto_exploit():
    """
    Full Automation Chain:
    Static Analysis -> Decompile+Scrape -> Payloads -> Live Exploit (لو فيه جهاز) -> Report
    """
    apk_path = console.input("\n[bold green][+] Enter APK Path: [/bold green]")

    console.print("\n[bold red][*] AUTO EXPLOIT — Full Automation Chain[/bold red]\n")

    # 1) Static Analysis
    console.print("[cyan][1/5][/cyan] Static analysis...")
    results, sensitive = run_full_pipeline(apk_path)

    table = Table(title="STATIC ANALYSIS REPORT")
    table.add_column("Category")
    table.add_column("Parameter")
    table.add_column("Value")
    table.add_column("Risk")

    for row in results:
        table.add_row(*[str(x) for x in row])

    for key in ["URLs", "Emails", "API Keys", "Tokens"]:
        values = sensitive.get(key, [])
        found = bool(values)
        value = ", ".join(values) if found else "Not Found"

        if not found:
            risk = "N/A"
        else:
            risk = "INFO"
            if key == "Emails":
                risk = "LOW"
            elif key == "API Keys":
                risk = "HIGH"
            elif key == "Tokens":
                risk = "CRITICAL"

        table.add_row("Secrets/APIs", key, value, risk)

    console.print(table)

    # 2) Decompile + Deep Secret Scan
    console.print("\n[cyan][2/5][/cyan] Decompiling APK for deep secrets scan...")
    extracted_dir = decompile_apk(apk_path)
    scraped = {"secrets": [], "endpoints": [], "injection": []}

    if extracted_dir:
        scraped = run_scraper(extracted_dir)
        console.print(
            f"[green][+][/green] Endpoints found: {len(scraped['endpoints'])} | "
            f"Secrets found: {len(scraped['secrets'])}"
        )
    else:
        console.print("[yellow][!] Decompilation failed (apktool موجود؟) — هنكمل من غير الفحص العميق.[/yellow]")

    # 3) Payload Generation
    console.print("\n[cyan][3/5][/cyan] Generating exploitation payloads...")
    all_payloads = []
    for endpoint in scraped.get("endpoints", [])[:3]:
        all_payloads.extend(generate_payloads(endpoint))

    if all_payloads:
        console.print(f"[green][+][/green] {len(all_payloads)} payloads generated from discovered endpoints.")
    else:
        console.print("[yellow][!] مفيش endpoints كفاية عشان نولد منها payloads.[/yellow]")

    # 4) Live Exploitation (لو فيه جهاز متوصل)
    console.print("\n[cyan][4/5][/cyan] Checking for connected device / live exploitation...")
    findings = []
    if check_adb():
        findings = run_attacks(results)
        if findings:
            console.print(f"[green][+][/green] {len(findings)} live findings triggered.")
        else:
            console.print("[green][+][/green] مفيش نتائج فعلية اتفعّلت.")
    else:
        console.print("[yellow][!] مفيش ADB device — بنتخطى مرحلة التنفيذ الفعلي.[/yellow]")

    # 5) Final Report
    console.print("\n[cyan][5/5][/cyan] Generating final report...")
    create_report(
        analysis_results=results,
        sensitive=sensitive,
        scraped=scraped,
        payloads=all_payloads,
        findings=findings,
        network_data=None  # ملحوظة: Auto Exploit مبيعملش infra scan؛ لو حابب تربطه بـ [2] INFRASTRUCTURE قولّي
    )

    input("\n[Press Enter to return]")


def main():
    while True:
        clear_screen()
        show_header()
        show_menu()

        choice = input("\nSelect Option: ")

        if choice == "1":
            mobile_audit()
        elif choice == "2":
            infrastructure_audit()
        elif choice == "3":
            attack_chain()
        elif choice == "4":
            auto_exploit()
        elif choice == "0":
            console.print("\n[bold yellow][*] Exiting B-XSSRF... Bye Mazen 👋[/bold yellow]\n")
            break
        else:
            console.print("\n[bold red][!] Invalid option, try again.[/bold red]")
            input("\n[Press Enter to continue]")


if __name__ == "__main__":
    main()
