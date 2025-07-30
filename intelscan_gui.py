# --- intelscan_gui.py ---
# This file provides the Gradio-based Graphical User Interface (GUI).
# It imports all its core functionality from the 'intel_scan_core' package.
# COMPATIBILITY: 'height' and 'row_count' parameters removed to support older Gradio versions.

import os
import datetime
import gradio as gr
import pandas as pd



# --- Import Core Logic ---
from intel_scan_core.logic import (
    sanitize_domain,
    get_dns_records,
    get_whois_info,
    parse_raw_whois_to_dataframe,
    perform_subdomain_scan,
    save_report
)

# --- Global Configurations ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(SCRIPT_DIR, 'results')
WORDLIST_PATH = os.path.join(SCRIPT_DIR, 'data', 'wordlists', 'common_subdomains.txt')
WORDLIST_EXISTS = os.path.exists(WORDLIST_PATH)


# --- Gradio Interface Functions (Event Handlers) ---

def handle_general_lookup(domain_input, all_results_state):
    target_domain = sanitize_domain(domain_input)
    if not target_domain:
        return None, None, gr.update(value="Error: Please enter a valid domain."), all_results_state
    
    all_results_state['domain'] = target_domain
    
    dns_data = get_dns_records(target_domain)
    dns_df = pd.DataFrame([(k, "\n".join(v)) for k,v in dns_data.items()], columns=["Record Type", "Value"]) if dns_data else pd.DataFrame()
    if dns_data: all_results_state['dns'] = dns_data
    
    whois_raw, whois_dict = get_whois_info(target_domain)
    whois_df = parse_raw_whois_to_dataframe(whois_raw) if whois_raw else pd.DataFrame()
    if whois_raw:
        all_results_state['raw_whois'] = whois_raw
        all_results_state['whois'] = whois_dict
        
    return dns_df, whois_df, gr.update(value=f"General lookup complete for {target_domain}."), all_results_state

def handle_subdomain_scan(domain_input, thread_choice, all_results_state, progress=gr.Progress()):
    target_domain = sanitize_domain(domain_input)
    if not target_domain:
        return None, "Error: Please enter a valid domain.", all_results_state
    
    all_results_state['domain'] = target_domain
    thread_map = {"Normal (50)": 50, "Fast (100)": 100, "Insane (200)": 200}
    thread_count = thread_map.get(thread_choice, 50)
    
    def progress_callback(current, total, description):
        if total > 0:
            progress(current / total, desc=description)

    try:
        subdomains = perform_subdomain_scan(target_domain, WORDLIST_PATH, thread_count, progress_callback)
    except FileNotFoundError:
        return None, f"ERROR: Wordlist not found at {WORDLIST_PATH}.", all_results_state
        
    if subdomains:
        all_results_state['subdomains'] = subdomains
        sub_df = pd.DataFrame(subdomains.items(), columns=["Subdomain", "IP Address"])
        status = f"Scan complete. Found {len(subdomains)} subs for {target_domain}."
    else:
        sub_df = pd.DataFrame()
        status = f"Scan complete. No active subdomains found for {target_domain}."
        
    return sub_df, gr.update(value=status), all_results_state
def handle_generate_report(report_format, all_results_state):
    domain = all_results_state.get('domain')
    if not all_results_state or not domain:
        return None, "No results to save. Please run a scan first."

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"intelscan_report_{domain}_{timestamp}.{report_format.lower()}"
    report_path = os.path.join(RESULTS_DIR, filename)

    save_report(RESULTS_DIR, domain, all_results_state, report_format)

    return gr.update(value=report_path, visible=True), f"{report_format} report generated."

def handle_clear_on_type(domain_input):
    sanitized = sanitize_domain(domain_input)
    new_state = {"domain": sanitized}
    return ("Ready", None, None, None, gr.update(value=None, visible=False), new_state)


# --- Gradio UI Definition ---

css = ".gradio-container {max-width: 1400px !important; margin: auto !important; background-color: #F8F9FA;} footer {display: none !important;} #sidebar {background-color: #FFFFFF; border-right: 1px solid #DEE2E6; padding: 20px !important; box-shadow: 2px 0px 5px 0px rgba(0,0,0,0.05);} #main_content {padding: 10px 20px !important;} .primary_action_button {background-color: #2563EB !important; color: white !important; border: none !important; border-radius: 8px !important; width: 100% !important; transition: background-color 0.2s ease-in-out !important; font-weight: 600 !important;} .primary_action_button:hover {background-color: #1D4ED8 !important;} #status_panel {background-color: #E9ECEF !important; border: 1px solid #CED4DA !important; text-align: center !important; font-weight: bold !important; font-size: 1.1em !important; padding: 12px !important;} #title_md {text-align: center;} #sidebar_title {margin-bottom: 0px; padding-bottom: 0px;} .gr-dataframe {border-radius: 8px !important;} #settings_accordion {background-color: #F8F9FA; border: 1px solid #DEE2E6 !important; border-radius: 8px !important; padding: 5px;}"
theme = gr.themes.Default(primary_hue=gr.themes.colors.blue).set(button_primary_background_fill_hover='*primary_600')

with gr.Blocks(theme=theme, css=css, title="Intel-Scan Pro") as demo:
    all_results_state = gr.State({})
    
    gr.Markdown("# 🛡️ Intel-Scan Pro (GUI)", elem_id="title_md")
    gr.Markdown("### Advanced DNS & Subdomain Discovery Tool", elem_id="title_md")
    
    with gr.Row(equal_height=False):
        with gr.Column(scale=2, elem_id="sidebar"):
            gr.Markdown("### Target", elem_id="sidebar_title")
            domain_input = gr.Textbox(label="Domain or URL", placeholder="e.g., tesla.com")
            
            gr.Markdown("### Actions")
            general_lookup_btn = gr.Button("🔍 DNS & WHOIS Lookup", elem_classes=["primary_action_button"])
            if WORDLIST_EXISTS:
                subdomain_scan_btn = gr.Button("🚀 Start Subdomain Scan", elem_classes=["primary_action_button"])
            else:
                 gr.Markdown("⚠️ **Warning:** Wordlist not found. Subdomain Scan is disabled.",)

            gr.Markdown("### Settings")
            with gr.Accordion("Subdomain Scan Speed", open=False, elem_id="settings_accordion"):
                thread_count_input = gr.Radio(["Normal (50)", "Fast (100)", "Insane (200)"], label=None, value="Normal (50)", show_label=False)
            
            gr.Markdown("### Export")
            report_format_input = gr.Radio(["TXT", "JSON", "Markdown",], label="Report Format", value="TXT")
            save_btn = gr.Button("💾 Generate & Save Report", elem_classes=["primary_action_button"])
            file_output = gr.File(label="Download Report", visible=False)
            
        with gr.Column(scale=5, elem_id="main_content"):
            status_panel = gr.Textbox(label="Scan Status", value="Ready", interactive=False, elem_id="status_panel")
            with gr.Tabs():
                with gr.TabItem("DNS Records"):
                    # NOTE: height and row_count removed for compatibility
                    dns_output = gr.DataFrame(headers=["Record Type", "Value"], wrap=True)
                with gr.TabItem("WHOIS Information"):
                    # NOTE: height and row_count removed for compatibility
                    whois_output = gr.DataFrame(headers=["Attribute", "Value"], wrap=True)
                with gr.TabItem("Found Subdomains"):
                    # NOTE: height and row_count removed for compatibility
                    subdomain_output = gr.DataFrame(headers=["Subdomain", "IP Address"], wrap=True)

    # --- Event Handlers ---
    domain_input.change(
        fn=handle_clear_on_type, 
        inputs=[domain_input], 
        outputs=[status_panel, dns_output, whois_output, subdomain_output, file_output, all_results_state]
    )
    general_lookup_btn.click(
        fn=handle_general_lookup,
        inputs=[domain_input, all_results_state],
        outputs=[dns_output, whois_output, status_panel, all_results_state]
    )
    if WORDLIST_EXISTS:
        subdomain_scan_btn.click(
            fn=handle_subdomain_scan,
            inputs=[domain_input, thread_count_input, all_results_state],
            outputs=[subdomain_output, status_panel, all_results_state]
        )
    save_btn.click(
        fn=handle_generate_report,
        inputs=[report_format_input, all_results_state],
        outputs=[file_output, status_panel]
    )

if __name__ == "__main__":
    demo.launch()