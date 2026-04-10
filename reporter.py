import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def create_report():
    console.print("\n[bold yellow][*] Generating Advanced Security Report...[/bold yellow]")
    
    # الجدول اللي بيظهر على الشاشة (للمعاينة السريعة)
    table = Table(title="[bold red]DETAILED VULNERABILITY REPORT[/bold red]", border_style="red")
    table.add_column("Phase", style="cyan", no_wrap=True)
    table.add_column("Key Findings & Data", style="white")

    # بيانات افتراضية (هنا ممكن تربطها بمتغيرات حقيقية من باقي الملفات)
    apk_data = "Found: API_KEY, FIREBASE_URL\nPath: /DivaApplication_extracted"
    network_data = "Open Port: 5000\nTarget: http://127.0.0.1:5000"
    payload_data = "Location: output/payloads/xss_bypass.svg"

    table.add_row("1. APK Analysis", apk_data)
    table.add_row("2. Payloads", payload_data)
    table.add_row("3. Network Scan", network_data)
    table.add_row("4. Recommendation", "[bold yellow]Fix Hardcoded Secrets & Close Port 5000[/bold yellow]")

    console.print(table)

    save_choice = input("\nDo you want to save this full report? (y/n): ").lower()
    
    if save_choice == 'y':
        filename = input("Enter filename (e.g., report.txt): ") or "final_report.txt"
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write("="*50 + "\n")
            f.write("       B-XSSRF v3.0 - PROFESSIONAL AUDIT REPORT\n")
            f.write("="*50 + "\n\n")
            
            f.write("[+] SECTION 1: EXTRACTED SECRETS (From APK)\n")
            f.write("-" * 35 + "\n")
            f.write(" - API_KEY: AIzaSy... (Check for Google Cloud Permissions)\n")
            f.write(" - FIREBASE: https://diva-auth.firebaseio.com\n\n")
            
            f.write("[+] SECTION 2: NETWORK INFRASTRUCTURE\n")
            f.write("-" * 35 + "\n")
            f.write(f" - Target IP: 127.0.0.1\n")
            f.write(f" - Open Ports Found: 5000 (upnp)\n")
            f.write(f" - Attack URL: http://127.0.0.1:5000/\n\n")
            
            f.write("[+] SECTION 3: GENERATED EXPLOITS\n")
            f.write("-" * 35 + "\n")
            f.write(" - Payload Path: output/payloads/xss_bypass.svg\n")
            f.write(" - Type: Obfuscated SVG (XSS/SSRF via onload)\n\n")
            
            f.write("[+] SECTION 4: RISK ASSESSMENT\n")
            f.write("-" * 35 + "\n")
            f.write(" - Severity: HIGH\n")
            f.write(" - Impact: Possible Data Leak & Unauthorized API Access\n")
            
            f.write("\n" + "="*50 + "\n")
            f.write("       END OF REPORT - SECURE YOUR SYSTEM\n")
            f.write("="*50 + "\n")
            
        console.print(f"[bold green][+][/bold green] Professional report saved to: [bold white]{filename}[/bold white]")
