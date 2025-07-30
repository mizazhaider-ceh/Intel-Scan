# --- intel_scan_core/logic.py ---
# This file contains the core "engine" of the application.
# All functions that perform scanning, data retrieval, and reporting are here.

import os
import json
import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# These libraries will need to be installed via pip
import dns.resolver
import whois
import pandas as pd

# --- Global Configurations ---
# Configure the DNS resolver for all functions that use it
resolver = dns.resolver.Resolver()
resolver.timeout = 2.0
resolver.lifetime = 5.0


# --- Data Retrieval and Parsing Functions ---

def sanitize_domain(domain_string: str) -> str:
    """Cleans up the user-provided domain or URL to get the base domain."""
    if not domain_string:
        return ""
    if not domain_string.startswith(('http://', 'https://')):
        domain_string = 'http://' + domain_string
    parsed = urlparse(domain_string)
    domain = parsed.netloc or parsed.path
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain.split('/')[0]

def get_dns_records(domain: str) -> dict | None:
    """Queries for common DNS records and returns them as a dictionary."""
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME']
    dns_results = {}
    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            dns_results[record_type] = [rdata.to_text() for rdata in answers]
        except dns.resolver.NoAnswer:
            dns_results[record_type] = ["No records found."]
        except Exception:
            continue
    return dns_results if dns_results else None

def get_whois_info(domain: str) -> tuple[str, dict] | tuple[None, None]:
    """
    Queries for WHOIS information.
    Returns both the raw text and a parsed dictionary.
    """
    try:
        domain_info = whois.whois(domain)
        if not domain_info.domain_name:
            return None, None
        return domain_info.text, domain_info.__dict__
    except Exception:
        return None, None

def parse_raw_whois_to_dataframe(raw_text: str) -> pd.DataFrame:
    """Parses a raw WHOIS text block into a two-column DataFrame for UI display."""
    if not raw_text:
        return pd.DataFrame(columns=["Attribute", "Value"])
    
    lines = raw_text.strip().splitlines()
    data = []
    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            if key.startswith('>>>'):
                continue
            data.append([key, value.strip()])
    
    return pd.DataFrame(data, columns=["Attribute", "Value"])


# --- Subdomain Scanning Functions ---

def _resolve_subdomain(subdomain: str) -> tuple[str, str | None]:
    """Resolves a single subdomain to an IP address (for use in threads)."""
    try:
        answers = resolver.resolve(subdomain, 'A')
        return subdomain, answers[0].to_text()
    except Exception:
        return subdomain, None

def perform_subdomain_scan(domain: str, wordlist_path: str, thread_count: int, progress_callback=None):
    """
    Performs a threaded subdomain scan.
    
    Args:
        domain (str): The target domain.
        wordlist_path (str): The full path to the subdomain wordlist file.
        thread_count (int): The number of threads to use.
        progress_callback (function, optional): A function to call to report progress.
                                                 It should accept (current, total, description).
    """
    try:
        with open(wordlist_path, 'r') as f:
            subdomains_to_check = [f"{line.strip()}.{domain}" for line in f if line.strip()]
    except FileNotFoundError:
        # The calling function (CLI or GUI) will handle this error message.
        raise

    found_subdomains = {}
    if progress_callback:
        progress_callback(0, len(subdomains_to_check), "Starting scan...")

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        tasks = {executor.submit(_resolve_subdomain, sub): sub for sub in subdomains_to_check}
        total_tasks = len(tasks)
        for i, future in enumerate(as_completed(tasks)):
            subdomain, ip = future.result()
            if ip:
                found_subdomains[subdomain] = ip
            if progress_callback:
                progress_callback(i + 1, total_tasks, f"Scanning: {subdomain}")

    return found_subdomains if found_subdomains else None


# --- Reporting Functions ---

def save_report(results_dir: str, domain: str, results_data: dict, report_format: str) -> str:
    """
    Generates and saves a report in the specified format.
    
    Args:
        results_dir (str): The directory where the report will be saved.
        domain (str): The target domain for the report.
        results_data (dict): The dictionary containing all scan data.
        report_format (str): The desired format ('TXT', 'JSON', 'Markdown').

    Returns:
        str: The full path to the generated report file.
    """
    os.makedirs(results_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_ext = report_format.lower()
    filename = os.path.join(results_dir, f"intelscan_report_{domain}_{timestamp}.{file_ext}")
    
    if report_format == "TXT":
        content = _create_txt_content(domain, results_data, timestamp)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
    elif report_format == "JSON":
        def json_encoder(obj):
            if isinstance(obj, (datetime.datetime, datetime.date)):
                return obj.isoformat()
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results_data, f, indent=4, default=json_encoder)
    elif report_format == "Markdown":
        content = _create_md_content(domain, results_data, timestamp)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
    # Note: PDF generation is complex and requires a library like FPDF.
    # We will only implement it in the GUI where it's most useful.
            
    return filename

def _create_txt_content(domain: str, results: dict, timestamp: str) -> str:
    """Helper function to generate the content for a TXT report."""
    content = [
        "="*80,
        " IntelScan Intelligence Report",
        "="*80,
        f"Target Domain:    {domain}",
        f"Report Generated: {timestamp}",
        "="*80 + "\n"
    ]
    if "raw_whois" in results and results["raw_whois"]:
        content.extend(["---[ WHOIS Information ]---\n", results["raw_whois"]])
    if "dns" in results and results["dns"]:
        content.append("\n---[ DNS Records ]---\n")
        for r_type, vals in sorted(results["dns"].items()):
            content.append(f"[ {r_type} ]\n" + "\n".join([f"  -> {v}" for v in vals]) + "\n")
    if "subdomains" in results and results["subdomains"]:
        content.append("\n---[ Found Subdomains ]---\n")
        for sub, ip in sorted(results["subdomains"].items()):
            content.append(f"{sub:<50} {ip}")
    return "\n".join(content)

def _create_md_content(domain: str, results: dict, timestamp: str) -> str:
    """Helper function to generate the content for a Markdown report."""
    content = [
        f"# IntelScan Report: `{domain}`",
        f"> _Report Generated: {timestamp}_",
        "---"
    ]
    if "raw_whois" in results and results["raw_whois"]:
        content.extend(["## WHOIS Information", "```text", results["raw_whois"], "```"])
    if "dns" in results and results["dns"]:
        content.append("## DNS Records")
        for r_type, vals in sorted(results["dns"].items()):
            content.extend([f"### {r_type} Records", *[f"* `{v}`" for v in vals]])
    if "subdomains" in results and results["subdomains"]:
        content.extend(["## Found Subdomains", "| Subdomain | IP Address |", "|:---|:---|",
                        *[f"| `{sub}` | `{ip}` |" for sub, ip in sorted(results["subdomains"].items())]])
    return "\n\n".join(content)