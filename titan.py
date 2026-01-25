import sys
import asyncio
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
async def run_titan_async():
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
        # Keep log limited to avoid memory leak in long scans
        if len(status_log["log_entries"]) > 100: status_log["log_entries"].pop(0)
        status_log["log_entries"].append(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}")

    async def engine_task():
        add_log(f"Initializing TitanRecon on {target}...")
        
        # 1. Critical Checks
        module_status["WAF"] = "[yellow]Scanning[/yellow]"
        try: 
            await detect_waf(target, scan_data, add_log)
            module_status["WAF"] = "[green]Done[/green]"
        except Exception as e: module_status["WAF"] = f"[red]Error: {e}[/red]"
        
        # 2. Parallel Passive Recon
        add_log("Launching Passive Modules...")
        
        passive_tasks = []
        
        # Headers
        async def task_headers():
            module_status["Headers"] = "[yellow]Fetching[/yellow]"
            await headers(target, None, scan_data)
            module_status["Headers"] = "[green]Done[/green]"
        passive_tasks.append(task_headers())

        # SSL
        async def task_ssl():
            module_status["SSL"] = "[yellow]Fetching[/yellow]"
            await cert(hostname, 443, None, scan_data)
            module_status["SSL"] = "[green]Done[/green]"
        passive_tasks.append(task_ssl())

        # Whois
        async def task_whois():
            module_status["Whois"] = "[yellow]Fetching[/yellow]"
            parts = hostname.split('.')
            if len(parts) >= 2:
                await whois_lookup(parts[-2], parts[-1], None, None, scan_data)
            module_status["Whois"] = "[green]Done[/green]"
        passive_tasks.append(task_whois())

        # Subdomains
        async def task_subdomains():
            module_status["Subdomains"] = "[yellow]Fetching[/yellow]"
            # Pass add_log as the logger argument
            await subdomains(hostname, 20, None, scan_data, None, logger=add_log)
            module_status["Subdomains"] = "[green]Done[/green]"
        passive_tasks.append(task_subdomains())

        # Wayback
        async def task_wayback():
             module_status["Wayback"] = "[yellow]Archiving[/yellow]"
             await timetravel(target, scan_data, None)
             module_status["Wayback"] = "[green]Done[/green]"
        passive_tasks.append(task_wayback())

        await asyncio.gather(*passive_tasks)
        add_log("[+] Passive Recon Completed.")

        # 3. Active Scanning (DNS + DirEnum + Ports concurrently? maybe too noisy. Let's group DNS and others)
        
        # DNS
        async def task_dns():
            module_status["DNS"] = "[yellow]Bruteforcing[/yellow]"
            await dnsrec(hostname, wordlist, None, scan_data, add_log)
            module_status["DNS"] = "[green]Done[/green]"

        # DirEnum
        async def task_dir():
            module_status["DirEnum"] = "[bold magenta]Enumerating[/bold magenta]"
            await hammer(target, 10, 5, None, False, False, None, scan_data, "php", add_log, wordlist)
            module_status["DirEnum"] = "[green]Done[/green]"

        # Ports
        async def task_ports():
            if nmap_flags:
                module_status["Ports"] = "[bold red]Scanning[/bold red]"
                # Need IP for nmap? The old code did resolution. Portscan handles it or we pass hostname?
                # The old code did: ip = socket.gethostbyname(hostname) before calling scan.
                # Let's resolve async or just let nmap handle hostname (slower but works).
                # But to allow nmap -Pn... pass IP or hostname is fine for nmap usually. 
                # Let's use hostname directly for simplicity, or confirm IP.
                # Since we already ran DNS, we might have it.
                # But standard resolution:
                try:
                    # Async resolution
                    loop = asyncio.get_running_loop()
                    try:
                        ip_info = await loop.getaddrinfo(hostname, None)
                        ip = ip_info[0][4][0]
                    except: ip = hostname
                    
                    await scan(ip, None, scan_data, None, add_log, nmap_flags)
                    module_status["Ports"] = "[green]Done[/green]"
                except Exception as e:
                     module_status["Ports"] = f"[red]Error[/red]"
                     add_log(f"[-] Portscan error: {e}")
            else:
                module_status["Ports"] = "[dim]Skipped[/dim]"

        # Launch active tasks
        # We can run DNS, Dir, Ports in parallel if the user wants "Full" speed.
        # But logging might get mixed. The UI handles it.
        # Let's run them:
        active_tasks = [task_dns(), task_dir(), task_ports()]
        await asyncio.gather(*active_tasks)

        add_log("Scan Finished. Generating Report...")
        report_file = save_report(scan_data, target)
        add_log(f"Report saved: {report_file}")
        status_log["Finished"] = True

    # Start the engine task
    loop = asyncio.get_running_loop()
    scan_task = loop.create_task(engine_task())
    
    start_time = datetime.datetime.now()
    
    # UI Loop
    with Live(create_layout(target, status_log, scan_data, module_status, start_time, 0), refresh_per_second=4, screen=True) as live:
        while not scan_task.done():
            live.update(create_layout(target, status_log, scan_data, module_status, start_time, 0))
            await asyncio.sleep(0.1)
        
        # One last update
        live.update(create_layout(target, status_log, scan_data, module_status, start_time, 0))
        
    # Check for exceptions
    if scan_task.exception():
        console.print(f"[bold red]Scan Task Failed with error: {scan_task.exception()}[/bold red]")
            
    console.clear()
    console.print(Panel(f"[bold green]SCAN COMPLETED[/bold green]\n\nTarget: {target}\nWAF: {scan_data.get('waf')}\nPorts Found: {len(scan_data.get('ports', []))}\nFiles Saved: reports/", title="TitanRecon Summary", border_style="green"))

def run_titan():
    import asyncio
    try:
        asyncio.run(run_titan_async())
    except KeyboardInterrupt:
        console.print("[red]\n[!] Aborted by user.[/red]")

if __name__ == "__main__":
    run_titan()