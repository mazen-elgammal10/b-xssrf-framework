import os
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.text import Text

# استيراد الموديولات
import unpacker, scraper, payload_factory, requester, reporter

console = Console()

def show_banner():
    os.system('clear')
    banner = Text("""
    ██████╗      ██╗  ██╗███████╗███████╗██████╗ ███████╗
    ██╔══██╗     ╚██╗██╔╝██╔════╝██╔════╝██╔══██╗██╔════╝
    ██████╔╝ █████╗╚███╔╝ ███████╗███████╗██████╔╝█████╗  
    ██╔══██╗ ╚════╝██╔██╗ ╚════██║╚════██║██╔══██╗██╔══╝  
    ██████╔╝      ██╔╝ ██╗███████║███████║██║  ██║██║     
    ╚═════╝       ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     
    """, style="bold red")
    banner.append(Text("\n               V3.0 - AUTOMATED PENTEST FRAMEWORK", style="bold blue"))
    console.print(Panel(banner, border_style="blue", expand=False))

def main():
    while True:
        show_banner()
        
        # الجدول بالترتيب الجديد 1، 2، 3
        table = Table(title="[bold red]COMMAND CENTER[/bold red]", border_style="blue", show_lines=True)
        table.add_column("ID", justify="center", style="bold blue")
        table.add_column("Module", style="bold white")
        table.add_column("Mode", justify="center")

        table.add_row("1", "APK Static Analysis", "[blue]Manual[/blue]")
        table.add_row("2", "Payload Generation", "[blue]Manual[/blue]")
        table.add_row("3", "SSRF Exploitation", "[blue]Manual[/blue]")
        table.add_row("4", "FULL AUTOMATION CHAIN", "[bold red]ULTIMATE[/bold red]")
        table.add_row("0", "Exit System", "[white]-[/white]")
        
        console.print(table)

        choice = Prompt.ask("\n[bold blue]Select Action[/bold blue]", choices=["0", "1", "2", "3", "4"])

        if choice == "1":
            path = unpacker.run()
            if path:
                scraper.run(path)
        
        elif choice == "2":
            payload_factory.generate()
            
        elif choice == "3":
            requester.start()
            
        elif choice == "4":
            console.print(Panel("STARTING AUTOMATED CHAIN", style="on red"))
            path = unpacker.run()
            if path:
                scraper.run(path)
                payload_factory.generate()
                requester.start()
                reporter.create_report()
            console.print("[bold green]\n[+] Chain Finished Successfully![/bold green]")
            
        elif choice == "0":
            console.print("[bold blue]Shutting down...[/bold blue]")
            break
            
        input("\nPress Enter to return to menu...")

if __name__ == "__main__":
    main()
