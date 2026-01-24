import sys
import time
import socket
import datetime
import threading
from rich.console import Console
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.tree import Tree
from rich.table import Table
from rich.prompt import Prompt
from rich.progress_bar import ProgressBar

console = Console()

# --- IMPORT MODULES ---
try:
    from modules.headers import headers
    from modules.sslinfo import cert
    from modules.whois import whois_lookup
    from modules.dns import dnsrec
    from modules.portscan import scan
    from modules.subdom import subdomains
    from modules.waf import detect_waf
    from modules.dirrec import hammer
    from modules.wayback import timetravel
    from modules.reporter import save_report
    MODULES_LOADED = True
except ImportError as e:
    MODULES_LOADED = False
    print(f"Error loading modules: {e}")

# --- CONFIGURATION MENU ---
def get_config():
    console.clear()
    console.print(Panel.fit("[bold white]TITAN RECON[/bold white] [dim]v1.0 - Community Edition[/dim]", border_style="cyan"))
    
    target = Prompt.ask("[bold cyan]Target URL[/bold cyan]", default="https://scanme.nmap.org", show_default=False)
    if not target.startswith(('http', 'https')): target = 'http://' + target

    default_wl = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    wordlist = Prompt.ask("[bold cyan]Wordlist Path[/bold cyan]", default=default_wl, show_default=False)
    
    console.print("\n[bold yellow]Select Scan Profile:[/bold yellow]")
    console.print("1. [green]Quiet[/green]    (Passive Only, No Nmap)")
    console.print("2. [cyan]Standard[/cyan] (Nmap -sV, DirEnum, WAF)")
    console.print("3. [red]Full[/red]     (All above + Aggressive Nmap -A)")
    
    choice = Prompt.ask("[bold cyan]Profile[/bold cyan]", choices=["1", "2", "3"], default="2", show_default=False)
    
    nmap_flags = "-sV -T4"
    if choice == "1": nmap_flags = None
    elif choice == "3": nmap_flags = "-A -T4"
    
    return target, wordlist, nmap_flags

# --- DASHBOARD LAYOUT ---
def create_layout(target, status_log, data, module_status, start_time, total_progress):
    layout = Layout()
    
    # Split: Header, Main Body, Footer (Progress)
    layout.split(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3)
    )
    
    # Split Body into 3 Vertical Columns
    layout["body"].split_row(
        Layout(name="tracker", ratio=1),
        Layout(name="terminal", ratio=2),
        Layout(name="surface", ratio=1)
    )
    
    # --- 1. HEADER ---
    elapsed = str(datetime.datetime.now() - start_time).split('.')[0]
    waf_status = data.get('waf', 'Checking...')
    header_text = f"Target: [bold green]{target}[/bold green] | WAF: {waf_status} | Elapsed: [bold yellow]{elapsed}[/bold yellow]"
    layout["header"].update(Panel(header_text, style="white on blue"))
    
    # --- 2. LEFT: MODULE TRACKER ---
    table = Table(show_header=True, header_style="bold magenta", expand=True)
    table.add_column("Module")
    table.add_column("Status")
    
    # Define the order of modules to show
    modules_order = ["WAF", "Headers", "SSL", "Whois", "DNS", "Subdomains", "Ports", "DirEnum", "Wayback"]
    
    for mod in modules_order:
        status = module_status.get(mod, "[dim]Waiting[/dim]")
        table.add_row(mod, status)
        
    layout["tracker"].update(Panel(table, title="[bold]Module Status[/bold]", border_style="magenta"))
    
    # --- 3. CENTER: SYSTEM TERMINAL ---
    log_text = Text()
    for entry in status_log["log_entries"][-22:]: 
        log_text.append(entry + "\n")
    layout["terminal"].update(Panel(log_text, title="[bold]System Terminal[/bold]", border_style="green"))
    
    # --- 4. RIGHT: ATTACK SURFACE ---
    tree = Tree("[bold gold1]Live Findings[/bold gold1]")
    
    if 'ports' in data and data['ports']:
        ports_branch = tree.add(f"[bold red]Open Ports ({len(data['ports'])})[/bold red]")
        for p in data['ports']:
            parts = p.split('|')
            if len(parts) > 2: ports_branch.add(f"[cyan]{parts[0].strip()}[/cyan] : {parts[2].strip()}")
    
    if 'subdomains' in data and data['subdomains']:
        sub_branch = tree.add(f"[bold blue]Subdomains ({len(data['subdomains'])})[/bold blue]")
        for s in data['subdomains'][:10]: sub_branch.add(s)
    
    if 'dir_enum' in data and data['dir_enum']:
        dir_branch = tree.add(f"[bold magenta]Hidden Dirs ({len(data['dir_enum'])})[/bold magenta]")
        for d in data['dir_enum'][-10:]: dir_branch.add(d)

    layout["surface"].update(Panel(tree, title="[bold]Attack Surface[/bold]", border_style="gold1"))

    # --- 5. FOOTER: PROGRESS BAR ---
    # We calculate percentage based on how many modules are "Done"
    completed = list(module_status.values()).count("[green]Done[/green]")
    total_modules = 9
    percent = (completed / total_modules) * 100
    
    bar = ProgressBar(total=100, completed=percent, width=None)
    layout["footer"].update(Panel(bar, title=f"Scan Progress: {int(percent)}%", border_style="blue"))

    return layout

# --- MAIN ENGINE ---
def run_titan():
    if not MODULES_LOADED:
        console.print("[bold red]CRITICAL: Missing Modules[/bold red]"); sys.exit(1)

    target, wordlist, nmap_flags = get_config()
    hostname = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    # Shared Data
    scan_data = {'waf': 'Pending...', 'ports': [], 'subdomains': [], 'dir_enum': []}
    status_log = {"log_entries": []}
    
    # Track status of each module for the Left Panel
    module_status = {
        "WAF": "[dim]Waiting[/dim]", "Headers": "[dim]Waiting[/dim]", "SSL": "[dim]Waiting[/dim]",
        "Whois": "[dim]Waiting[/dim]", "DNS": "[dim]Waiting[/dim]", "Subdomains": "[dim]Waiting[/dim]",
        "Ports": "[dim]Waiting[/dim]", "DirEnum": "[dim]Waiting[/dim]", "Wayback": "[dim]Waiting[/dim]"
    }
    
    def add_log(msg):
        status_log["log_entries"].append(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}")

    def engine():
        add_log(f"Initializing TitanRecon on {target}...")
        
        # 1. Critical Checks
        module_status["WAF"] = "[yellow]Scanning[/yellow]"
        try: 
            detect_waf(target, scan_data, add_log)
            module_status["WAF"] = "[green]Done[/green]"
        except: module_status["WAF"] = "[red]Error[/red]"
        
        # 2. Parallel Passive Recon
        add_log("Launching Passive Modules...")
        
        # Set statuses
        module_status["Headers"] = "[yellow]Fetching[/yellow]"
        module_status["SSL"] = "[yellow]Fetching[/yellow]"
        module_status["Whois"] = "[yellow]Fetching[/yellow]"
        module_status["Subdomains"] = "[yellow]Fetching[/yellow]"

        threads = []
        threads.append(threading.Thread(target=headers, args=(target, None, scan_data)))
        threads.append(threading.Thread(target=cert, args=(hostname, 443, None, scan_data)))
        threads.append(threading.Thread(target=whois_lookup, args=(hostname.split('.')[-2], hostname.split('.')[-1], None, None, scan_data)))
        threads.append(threading.Thread(target=subdomains, args=(hostname, 20, None, scan_data, None)))
        
        for t in threads: t.start()
        for t in threads: t.join()
        
        # Update statuses
        module_status["Headers"] = "[green]Done[/green]"
        module_status["SSL"] = "[green]Done[/green]"
        module_status["Whois"] = "[green]Done[/green]"
        module_status["Subdomains"] = "[green]Done[/green]"
        
        add_log("[+] Passive Recon Completed.")

        # 3. Active Scanning
        module_status["DNS"] = "[yellow]Bruteforcing[/yellow]"
        try: 
            dnsrec(hostname, wordlist, None, scan_data, add_log)
            module_status["DNS"] = "[green]Done[/green]"
        except: module_status["DNS"] = "[red]Error[/red]"
        
        if nmap_flags:
            module_status["Ports"] = "[bold red]Scanning[/bold red]"
            try:
                ip = socket.gethostbyname(hostname)
                scan(ip, None, scan_data, None, add_log, nmap_flags)
                module_status["Ports"] = "[green]Done[/green]"
            except: 
                add_log("[-] Host resolution failed for Nmap.")
                module_status["Ports"] = "[red]Error[/red]"
        else:
            module_status["Ports"] = "[dim]Skipped[/dim]"
            
        module_status["DirEnum"] = "[bold magenta]Enumerating[/bold magenta]"
        try: 
            hammer(target, 10, 5, None, False, False, None, scan_data, "php", add_log, wordlist)
            module_status["DirEnum"] = "[green]Done[/green]"
        except: module_status["DirEnum"] = "[red]Error[/red]"
            
        module_status["Wayback"] = "[yellow]Archiving[/yellow]"
        try: 
            timetravel(target, scan_data, None)
            module_status["Wayback"] = "[green]Done[/green]"
        except: module_status["Wayback"] = "[red]Error[/red]"

        add_log("Scan Finished. Generating Report...")
        report_file = save_report(scan_data, target)
        add_log(f"Report saved: {report_file}")
        status_log["Finished"] = True

    t = threading.Thread(target=engine)
    t.start()
    
    start_time = datetime.datetime.now()
    
    with Live(create_layout(target, status_log, scan_data, module_status, start_time, 0), refresh_per_second=4, screen=True) as live:
        while True:
            live.update(create_layout(target, status_log, scan_data, module_status, start_time, 0))
            if "Finished" in status_log:
                time.sleep(2)
                break
            time.sleep(0.1)
            
    console.clear()
    console.print(Panel(f"[bold green]SCAN COMPLETED[/bold green]\n\nTarget: {target}\nWAF: {scan_data.get('waf')}\nPorts Found: {len(scan_data.get('ports', []))}\nFiles Saved: reports/", title="TitanRecon Summary", border_style="green"))

if __name__ == "__main__":
    try: run_titan()
    except KeyboardInterrupt: console.print("[red]\n[!] Aborted by user.[/red]")