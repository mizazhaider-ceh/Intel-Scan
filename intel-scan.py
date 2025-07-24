# intelscan.py
# Creator: Muhammad Izaz Haider

# gotta import all the stuff i need for this to work
import os
import sys
import socket
import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# these are the special libraries that do the heavy lifting
import dns.resolver
import whois

# this 'rich' library is what makes the output look so cool
from rich.align import Align
from rich.box import ROUNDED, HEAVY
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

# --- setting things up before we start ---
console = Console() # this is the main thing for rich to print colors etc
resolver = dns.resolver.Resolver() # for all the dns lookups
resolver.timeout = 2.0 # so it doesn't wait forever
resolver.lifetime = 5.0

# finding where the script is, so it can find the other files
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# where my list of subdomains is
WORDLIST_PATH = os.path.join(SCRIPT_DIR, 'data', 'wordlists', 'common_subdomains.txt')
# where the reports will be saved
RESULTS_DIR = os.path.join(SCRIPT_DIR, 'results')


def print_banner():
    # just prints the cool ascii art banner
    banner_text = """
                ██╗███╗   ██╗████████╗███████╗██╗         ███████╗ ██████╗ █████╗ ███╗   ██╗
                ██║████╗  ██║╚══██╔══╝██╔════╝██║         ██╔════╝██╔════╝██╔══██╗████╗  ██║
                ██║██╔██╗ ██║   ██║   █████╗  ██║         ███████╗██║     ███████║██╔██╗ ██║
                ██║██║╚██╗██║   ██║   ██╔══╝  ██║         ╚════██║██║     ██╔══██║██║╚██╗██║
                ██║██║ ╚████║   ██║   ███████╗███████╗    ███████║╚██████╗██║  ██║██║ ╚████║
                ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝                                                                            
    """
    title = "[bold bright_cyan]IntelScan: A Professional DNS & Subdomain Discovery Tool[/bold bright_cyan]"
    byline = "[yellow]by Muhammad Izaz Haider[/yellow]"
    console.rule(style="bold blue")
    console.print(Align.center(banner_text, style="yellow"))
    console.print(Align.center(title))
    console.print(Align.center(byline))
    console.rule(style="bold blue")

def sanitize_domain(domain_string: str) -> str:
    # a small helper to clean up the domain name the user enters
    # so we get 'google.com' from 'http://www.google.com/search'
    parsed = urlparse(domain_string)
    domain = parsed.netloc or parsed.path
    if domain.startswith('www.'): domain = domain[4:]
    return domain.split('/')[0]

def get_dns_records(domain: str) -> dict | None:
    # this function gets all the main dns records
    console.print(Panel("[bold cyan]Querying DNS Records...[/bold cyan]", expand=False, border_style="dim"))
    # list of dns types i want to check
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME']
    dns_results = {}
    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            dns_results[record_type] = [rdata.to_text() for rdata in answers]
        except: # just ignore if a record type is not found
            continue
    if not dns_results:
        console.print("[yellow][-] No common DNS records were found.[/yellow]"); return None
    # using rich to make the output look nice in a table
    table = Table(title=f"DNS Records for [bold]{domain}[/bold]", box=ROUNDED, style="cyan", title_style="bold bright_cyan")
    table.add_column("Record Type", style="bold magenta", justify="right")
    table.add_column("Value", style="green")
    for record_type, values in sorted(dns_results.items()):
        table.add_row(record_type, "\n".join(values))
    console.print(table)
    return dns_results

def get_whois_info(domain: str) -> dict | None:
    # getting the whois details, like who owns the domain
    console.print(Panel("[bold cyan]Querying Full WHOIS Information...[/bold cyan]", expand=False, border_style="dim"))
    try:
        domain_info = whois.whois(domain)
        if not domain_info.domain_name:
            console.print("[red][!] Could not retrieve WHOIS information.[/red]"); return None
        # again, using a rich table for cool output
        table = Table(title=f"WHOIS Report for [bold]{domain}[/bold]", box=ROUNDED, style="cyan", title_style="bold bright_cyan")
        table.add_column("Attribute", style="bold magenta", justify="right")
        table.add_column("Value", style="green")
        domain_info_dict = domain_info.__dict__
        # looping through the results to make it look nice in the table
        for key, value in domain_info_dict.items():
            if value:
                display_key = key.replace('_', ' ').title()
                if isinstance(value, list):
                    value_str = "\n".join([str(item) for item in value])
                else:
                    value_str = str(value)
                table.add_row(display_key, value_str)
        console.print(table)
        return domain_info_dict
    except Exception as e:
        console.print(f"[red][!] An error occurred during WHOIS lookup: {e}[/red]"); return None

def resolve_subdomain(subdomain: str) -> tuple[str, str | None]:
    # this is the small function that each thread will run
    # it just checks if a subdomain is real or not by looking for an 'A' record
    try:
        answers = resolver.resolve(subdomain, 'A')
        return subdomain, answers[0].to_text()
    except:
        return subdomain, None

def perform_subdomain_scan(domain: str, thread_count: int) -> dict | None:
    # this is the main scan function for subdomains
    console.print(Panel(f"[bold cyan]Starting High-Speed Subdomain Scan for [bold]{domain}[/bold][/bold cyan]", expand=False, border_style="dim"))
    try:
        # first open the wordlist and create the full subdomain names
        with open(WORDLIST_PATH, 'r') as f:
            subdomains_to_check = [f"{line.strip()}.{domain}" for line in f if line.strip()]
        console.print(f"[green][i] Loaded {len(subdomains_to_check)} potential subdomains from wordlist.[/green]")
    except FileNotFoundError:
        console.print(f"[red][!] Wordlist not found at '{WORDLIST_PATH}'.[/red]"); return None
    
    found_subdomains = {}
    # this rich progress bar looks so cool while scanning
    progress = Progress(SpinnerColumn(), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                        TextColumn("•"), TextColumn("[progress.description]{task.description}"), transient=True)
    with progress:
        task = progress.add_task(f"Scanning with {thread_count} threads...", total=len(subdomains_to_check))
        # this is the magic part that makes it fast - using threads
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            tasks = {executor.submit(resolve_subdomain, sub): sub for sub in subdomains_to_check}
            # as each thread finishes, we get the result
            for future in as_completed(tasks):
                subdomain, ip = future.result()
                if ip: # if an ip was found, it's a live subdomain
                    found_subdomains[subdomain] = ip
                progress.update(task, advance=1) # update the progress bar
    if not found_subdomains:
        console.print("\n[yellow][-] Scan Complete. No active subdomains found.[/yellow]"); return None
    # print the results in another nice table
    table = Table(title=f"Found Subdomains for [bold]{domain}[/bold]", box=ROUNDED, style="cyan", title_style="bold bright_cyan")
    table.add_column("Subdomain", style="bold magenta", max_width=50)
    table.add_column("IP Address", style="green")
    for subdomain, ip in sorted(found_subdomains.items()):
        table.add_row(subdomain, ip)
    console.print(table)
    return found_subdomains

def save_results(domain: str, results: dict):
    # saving everything to a text file
    os.makedirs(RESULTS_DIR, exist_ok=True)
    # make the filename unique with the date and time
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = os.path.join(RESULTS_DIR, f"intelscan_report_{domain}_{timestamp}.txt")
    with open(filename, 'w', encoding='utf-8') as f:
        # writing a nice header for the report
        f.write("="*80 + "\n" + f" IntelScan Intelligence Report\n" + "="*80 + "\n")
        f.write(f"Target Domain:    {domain}\n" + f"Report Generated: {timestamp}\n" + "="*80 + "\n\n")
        # writing the different sections of the report
        if "dns" in results and results["dns"]:
            f.write("---[ DNS Records ]---\n")
            for r_type, vals in sorted(results["dns"].items()):
                f.write(f"\n[ {r_type} ]\n" + "\n".join([f"  -> {v}" for v in vals]) + "\n")
            f.write("\n")
        if "whois" in results and results["whois"]:
            f.write("---[ WHOIS Information ]---\n\n")
            for k, v in results["whois"].items():
                if v and not k.startswith("ldap"):
                    display_key = k.replace('_', ' ').title()
                    if isinstance(v, list): f.write(f"{display_key}:\n" + "\n".join([f"  -> {item}" for item in v]) + "\n")
                    else: f.write(f"{display_key+':':<25} {v}\n")
            f.write("\n")
        if "subdomains" in results and results["subdomains"]:
            f.write("---[ Found Subdomains ]---\n\n")
            results_by_ip = {}
            for sub, ip in results["subdomains"].items():
                if ip not in results_by_ip: results_by_ip[ip] = []
                results_by_ip[ip].append(sub)
            for ip, subs in sorted(results_by_ip.items()):
                f.write(f"IP Address: {ip}\n" + "\n".join([f"  -> {sub}" for sub in sorted(subs)]) + "\n\n")
    console.print(Panel(f"[bold green]✔ Comprehensive report saved to [bold cyan]{filename}[/bold cyan][/bold green]", expand=False, border_style="green"))


def get_target():
    # ask the user for the website to scan
    console.rule("[bold yellow]Enter Target Domain[/bold yellow]")
    target_input = console.input(f"[bold bright_cyan]Enter the target domain (e.g., tesla.com): [/bold bright_cyan]").strip()
    if not target_input:
        console.print("[red][!] No domain entered.[/red]")
        return None
    sanitized = sanitize_domain(target_input)
    console.print(f"[green][i] New target set to: [bold]{sanitized}[/bold][/green]")
    return sanitized

def main():
    # the main brain of the tool
    os.system('cls' if os.name == 'nt' else 'clear') # clear the screen first
    print_banner()

    # first, check if the wordlist file is even there, otherwise it will crash
    if not os.path.exists(WORDLIST_PATH):
        console.print(Panel(
            f"[bold red]Startup Error: Wordlist Not Found![/bold red]\n\n"
            f"IntelScan requires a wordlist file for subdomain scanning.\n"
            f"It was not found at this location:\n[yellow]{WORDLIST_PATH}[/yellow]",
            title="[bold yellow]Configuration Needed[/bold yellow]", border_style="red"
        ))
        return

    target_domain = get_target()
    if not target_domain: return
    
    # an empty dictionary to hold all the results we find
    all_results = {}

    # this `while` loop keeps the menu running forever until they exit
    while True:
        console.rule(f"[bold yellow]IntelScan Menu | Current Target: [bold bright_cyan]{target_domain}[/bold bright_cyan][/bold yellow]")
        console.print("[bold green][1][/bold green] General Intelligence Lookup (DNS & WHOIS)")
        if WORDLIST_PATH:
            console.print("[bold green][2][/bold green] High-Speed Subdomain Scan")
        console.print("[bold green][S][/bold green] Save All Collected Results to File")
        console.print("[bold green][C][/bold green] Change Target Domain")
        console.print("[bold green][0][/bold green] Exit")
        choice = console.input(f"[bold bright_cyan]Select an option: [/bold bright_cyan]").strip().upper()

        # this part handles what the user picks from the menu
        if choice == '1':
            all_results["dns"] = get_dns_records(target_domain)
            all_results["whois"] = get_whois_info(target_domain)
        elif choice == '2' and WORDLIST_PATH:
            console.print(Panel("[bold yellow]---[ Subdomain Scan Speed ]---[/bold yellow]", expand=False, border_style="yellow"))
            console.print("[bold green][1][/bold green] Normal (50 threads)")
            console.print("[bold green][2][/bold green] Fast (100 threads)")
            console.print("[bold green][3][/bold green] Insane (150 threads)")
            speed_choice = console.input(f"[bold bright_cyan]Select speed: [/bold bright_cyan]").strip()
            thread_count = 50 # default speed
            if speed_choice == '2': thread_count = 100
            elif speed_choice == '3': thread_count = 150
            all_results["subdomains"] = perform_subdomain_scan(target_domain, thread_count)
        elif choice == 'S':
            if not all_results:
                console.print("[yellow][!] No results collected yet to save.[/yellow]")
            else:
                save_results(target_domain, all_results)
        elif choice == 'C':
            new_target = get_target()
            if new_target:
                target_domain = new_target
                all_results = {} # clear results for the new target
        elif choice == '0':
            console.print(f"[yellow]Exiting IntelScan... Thank you for using the tool![/yellow]")
            break # this breaks the while loop and ends the program
        else:
            console.print(f"[red][!] Invalid option. Please try again.[/red]")

# this makes the script run when i call it from the terminal
if __name__ == "__main__":
    main()