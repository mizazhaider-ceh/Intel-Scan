# --- intelscan_cli.py ---
# This file provides the Command-Line Interface (CLI) for the tool.
# It imports all its core functionality from the 'intel_scan_core' package.

import os
import sys

# --- Required Libraries ---
# Note: 'rich' must be installed for this to work.
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.align import Align

# --- Import Core Logic ---
# This is the key to our clean architecture. We are importing the "engine".
from intel_scan_core.logic import (
    sanitize_domain,
    get_dns_records,
    get_whois_info,
    perform_subdomain_scan,
    save_report
)

# --- Global Configurations ---
console = Console() # For all beautiful printing
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(SCRIPT_DIR, 'results')
WORDLIST_PATH = os.path.join(SCRIPT_DIR, 'data', 'wordlists', 'common_subdomains.txt')


# --- CLI Display Functions ---

def print_banner():
    """Prints the main welcome banner for the tool."""
    banner_text = "🛡️ [bold bright_cyan]Intel-Scan[/bold bright_cyan] 🛡️"
    byline = "[yellow]The Professional OSINT Discovery Tool (CLI)[/yellow]"
    console.rule(style="bold blue")
    console.print(Align.center(banner_text, style="yellow", vertical="middle"))
    console.print(Align.center(byline))
    console.rule(style="bold blue")

def display_dns_results(domain: str, dns_data: dict):
    """Displays DNS records in a clean table."""
    if not dns_data:
        console.print("[yellow][-] No common DNS records were found.[/yellow]")
        return
    
    table = Table(title=f"DNS Records for [bold]{domain}[/bold]", box=None, style="cyan", title_style="bold bright_cyan")
    table.add_column("Record Type", style="bold magenta", justify="right")
    table.add_column("Value", style="green")
    
    for record_type, values in sorted(dns_data.items()):
        table.add_row(record_type, "\n".join(values))
    console.print(table)

def display_whois_results(domain: str, whois_text: str):
    """Displays raw WHOIS information in a panel."""
    if not whois_text:
        console.print("[red][!] Could not retrieve WHOIS information.[/red]")
        return
        
    panel = Panel(
        whois_text,
        title=f"WHOIS Report for [bold]{domain}[/bold]",
        border_style="cyan",
        title_align="left"
    )
    console.print(panel)
    
def display_subdomain_results(domain: str, subdomains: dict):
    """Displays found subdomains in a table."""
    if not subdomains:
        console.print("\n[yellow][-] Scan Complete. No active subdomains found.[/yellow]")
        return
    
    table = Table(title=f"Found Subdomains for [bold]{domain}[/bold]", box=None, style="cyan", title_style="bold bright_cyan")
    table.add_column("Subdomain", style="bold magenta", max_width=50)
    table.add_column("IP Address", style="green")
    
    for subdomain, ip in sorted(subdomains.items()):
        table.add_row(subdomain, ip)
    console.print(table)


# --- Main Application Logic ---

def main():
    """The main function that runs the interactive CLI menu."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()

    if not os.path.exists(WORDLIST_PATH):
        console.print(Panel(
            f"[bold red]Startup Error: Wordlist Not Found![/bold red]\n\n"
            f"The wordlist for subdomain scanning was not found at:\n[yellow]{WORDLIST_PATH}[/yellow]",
            title="[bold yellow]Configuration Needed[/bold yellow]", border_style="red"
        ))
        return

    console.rule("[bold yellow]Enter Target Domain[/bold yellow]")
    target_input = console.input("[bold bright_cyan]Enter target (e.g., tesla.com): [/bold bright_cyan]").strip()
    target_domain = sanitize_domain(target_input)
    if not target_domain:
        console.print("[red][!] No valid domain entered. Exiting.[/red]")
        return
    
    all_results = {"domain": target_domain}

    while True:
        console.rule(f"[bold yellow]Menu | Target: [bold bright_cyan]{target_domain}[/bold bright_cyan][/bold yellow]")
        console.print("[bold green][1][/bold green] General Lookup (DNS & WHOIS)")
        console.print("[bold green][2][/bold green] Subdomain Scan")
        console.print("[bold green][S][/bold green] Save All Results to File")
        console.print("[bold green][C][/bold green] Change Target")
        console.print("[bold green][0][/bold green] Exit")
        choice = console.input("[bold bright_cyan]Select an option: [/bold bright_cyan]").strip().upper()

        if choice == '1':
            console.print(Panel("[bold cyan]Querying DNS Records...[/bold cyan]", expand=False))
            all_results["dns"] = get_dns_records(target_domain)
            display_dns_results(target_domain, all_results["dns"])
            
            console.print(Panel("[bold cyan]Querying WHOIS Information...[/bold cyan]", expand=False))
            raw_whois, whois_dict = get_whois_info(target_domain)
            all_results["raw_whois"] = raw_whois
            all_results["whois"] = whois_dict
            display_whois_results(target_domain, raw_whois)

        elif choice == '2':
            console.print(Panel("[bold yellow]---[ Scan Speed ]---[/bold yellow]", expand=False))
            console.print("[1] Normal (50)  [2] Fast (100)  [3] Insane (200)")
            speed_choice = console.input("[bold bright_cyan]Select speed: [/bold bright_cyan]").strip()
            speed_map = {'1': 50, '2': 100, '3': 200}
            thread_count = speed_map.get(speed_choice, 50) # Default to 50

            # Define the progress bar for the scan
            progress = Progress(
                SpinnerColumn(),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("•"),
                TextColumn("[progress.description]{task.description}"),
                transient=True
            )
            
            with progress:
                task = progress.add_task(f"Scanning with {thread_count} threads...", total=None) # Indeterminate at first
                def progress_callback(current, total, description):
                    if progress.tasks[task].total is None:
                        progress.update(task, total=total) # Set total once we know it
                    progress.update(task, completed=current, description=description)

                try:
                    found_subs = perform_subdomain_scan(target_domain, WORDLIST_PATH, thread_count, progress_callback)
                    all_results["subdomains"] = found_subs
                    display_subdomain_results(target_domain, found_subs)
                except FileNotFoundError:
                     console.print(f"[red][!] Wordlist not found at '{WORDLIST_PATH}'.[/red]")

        elif choice == 'S':
            if len(all_results) <= 1:
                console.print("[yellow][!] No results collected yet to save.[/yellow]")
            else:
                report_path = save_report(RESULTS_DIR, target_domain, all_results, 'TXT')
                console.print(Panel(f"[bold green]✔ Report saved to [cyan]{report_path}[/cyan][/bold green]"))

        elif choice == 'C':
            console.rule("[bold yellow]Enter New Target Domain[/bold yellow]")
            new_target_input = console.input("[bold bright_cyan]Enter new target: [/bold bright_cyan]").strip()
            new_target = sanitize_domain(new_target_input)
            if new_target:
                target_domain = new_target
                all_results = {"domain": target_domain} # Reset results for the new target
                console.print(f"[green][i] Target changed to: [bold]{target_domain}[/bold][/green]")
            else:
                console.print("[red][!] Invalid new target.[/red]")

        elif choice == '0':
            console.print("[yellow]Exiting Intel-Scan... Goodbye![/yellow]")
            break
        else:
            console.print("[red][!] Invalid option. Please try again.[/red]")


if __name__ == "__main__":
    main()