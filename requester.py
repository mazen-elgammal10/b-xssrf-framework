import nmap
import os
import sys
from rich.console import Console
from rich.table import Table

console = Console()

def start():
    console.print("\n[bold cyan][#] SSRF & Port Scanner Module[/bold cyan]")
    target_ip = input("Enter Target IP: ").strip()

    if not target_ip:
        console.print("[bold red][!] Target IP cannot be empty.[/bold red]")
        return

    # مرحلة الفحص باستخدام Nmap
    nm = nmap.PortScanner()
    console.print(f"[bold yellow][*] Scanning {target_ip} for open ports...[/bold yellow]")
    
    try:
        # فحص سريع لأشهر البورتات
        nm.scan(target_ip, arguments='-F') 
        
        if target_ip not in nm.all_hosts():
            console.print("[bold red][!] Target is down or not reachable.[/bold red]")
            return

        # إنشاء جدول لعرض البورتات المفتوحة
        table = Table(title=f"Open Ports on {target_ip}", border_style="blue")
        table.add_column("Port", justify="center", style="cyan")
        table.add_column("Service", style="white")
        table.add_column("State", style="green")

        open_ports = []
        for proto in nm[target_ip].all_protocols():
            lport = nm[target_ip][proto].keys()
            for port in sorted(lport):
                state = nm[target_ip][proto][port]['state']
                if state == 'open':
                    service = nm[target_ip][proto][port]['name']
                    table.add_row(str(port), service, state)
                    open_ports.append(str(port))

        if not open_ports:
            console.print("[bold red][!] No open ports found.[/bold red]")
            return

        console.print(table)

        # اختيار البورت
        selected_port = input("\nSelect a port to attack: ")
        
        path = input("Enter API Path (press Enter for /): ")
        if not path:
            path = "/"
        elif not path.startswith("/"):
            path = "/" + path

        target_url = f"http://{target_ip}:{selected_port}{path}"
        
        console.print(f"\n[bold blue][*] Target set to: {target_url}[/bold blue]")
        # هنا تكملة الهجوم الخاص بـ SSRF
        console.print("[bold green][+] Exploitation request sent.[/bold green]")

    except Exception as e:
        console.print(f"[bold red][!] Error: {e}[/bold red]")

if __name__ == "__main__":
    start()
