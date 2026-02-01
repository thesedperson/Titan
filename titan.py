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
    from modules.client import TitanClient
    from modules.s3 import s3_enum
    from modules.fingerprint import fingerprint_tech
    MODULES_LOADED = True
except ImportError as e:
    MODULES_LOADED = False
    print(f"Error loading modules: {e}")

# --- CONFIGURATION MENU ---
def get_config():
    console.clear()
    
    # Flashy Banner using Rich Panel and alignment
    from rich.align import Align
    banner_text = """
 [bold magenta]████████╗██╗████████╗ █████╗ ███╗   ██╗[/bold magenta]    [bold cyan]██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗[/bold cyan]
 [bold magenta]╚══██╔══╝██║╚══██╔══╝██╔══██╗████╗  ██║[/bold magenta]    [bold cyan]██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║[/bold cyan]
    [bold magenta]██║   ██║   ██║   ███████║██╔██╗ ██║[/bold magenta]    [bold cyan]██████╔╝█████╗  ██║     ██║  ██║██╔██╗ ██║[/bold cyan]
    [bold magenta]██║   ██║   ██║   ██╔══██║██║╚██╗██║[/bold magenta]    [bold cyan]██╔══██╗██╔══╝  ██║     ██║  ██║██║╚██╗██║[/bold cyan]
    [bold magenta]██║   ██║   ██║   ██║  ██║██║ ╚████║[/bold magenta]    [bold cyan]██║  ██║███████╗╚██████╗╚██████╗██║ ╚████║[/bold cyan]
    [bold magenta]╚═╝   ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝[/bold magenta]    [bold cyan]╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚═══╝[/bold cyan]
    """
    subtitle = "[bold white]The Ultimate Penetration Testing Enumerator[/bold white]\n[dim]v2.1 • Built for Speed • Designed for Hackers[/dim]"
    
    panel = Panel(
        Align.center(banner_text + "\n" + subtitle),
        border_style="bright_blue",
        padding=(1, 2)
    )
    console.print(panel)
    
    target = Prompt.ask("[bold cyan]Target URL[/bold cyan]", default="https://scanme.nmap.org", show_default=False)
    if not target.startswith(('http', 'https')): target = 'http://' + target

    default_wl = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    wordlist = Prompt.ask("[bold cyan]Wordlist Path[/bold cyan]", default=default_wl, show_default=False)
    
    console.print("\n[bold yellow]Select Scan Profile:[/bold yellow]")
    console.print("1. [green]Quiet[/green]    (Passive Only, No Nmap, No Brute-force)")
    console.print("2. [cyan]Standard[/cyan] (Nmap -sV, DirEnum, WAF, S3, Tech)")
    console.print("3. [red]Full[/red]     (All above + Aggressive Nmap -A + Full DNS AXFR)")
    
    choice = Prompt.ask("[bold cyan]Profile[/bold cyan]", choices=["1", "2", "3"], default="2", show_default=False)
    
    nmap_flags = "-sV -T4"
    if choice == "1": nmap_flags = None
    elif choice == "2": nmap_flags = "-F -sV -T4" # Standard: Fast Top 100 + Version
    elif choice == "3": nmap_flags = "-A -T4"      # Full: Top 1000 + Aggressive
    
    return target, wordlist, nmap_flags

# --- DASHBOARD LAYOUT ---
def create_layout(target, status_log, data, module_status, start_time, total_progress):
    from rich.markup import escape
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3)
    )
    
    layout["body"].split_row(
        Layout(name="tracker", ratio=2, minimum_size=30),
        Layout(name="terminal", ratio=3, minimum_size=40),
        Layout(name="surface", ratio=2, minimum_size=30)
    )
    
    # HEADER
    elapsed = str(datetime.datetime.now() - start_time).split('.')[0]
    waf_status = data.get('waf', 'Checking...')
    waf_style = "bold red" if "Detected" in waf_status else "bold green"
    header_text = f"Target: [bold green]{escape(target)}[/bold green] | WAF: [{waf_style}]{escape(waf_status)}[/{waf_style}] | Elapsed: [bold yellow]{elapsed}[/bold yellow]"
    layout["header"].update(Panel(header_text, style="white on blue"))
    
    # TRACKER
    table = Table(show_header=True, header_style="bold magenta", expand=True)
    table.add_column("Module")
    table.add_column("Status")
    
    modules_order = ["WAF", "Tech", "S3", "Headers", "SSL", "Whois", "DNS", "Subdomains", "Ports", "DirEnum", "Wayback"]
    for mod in modules_order:
        status = module_status.get(mod, "[dim]Waiting[/dim]")
        table.add_row(mod, status)
        
    layout["tracker"].update(Panel(table, title="[bold]Module Status[/bold]", border_style="magenta"))
    
    # TERMINAL
    log_text = Text()
    for entry in status_log["log_entries"][-22:]: 
        # Log entries might contain brackets, but since we append to Text() object directly, 
        # it treats them as literals unless we used Text.from_markup. 
        # However, to be extra safe if logic changes:
        log_text.append(entry + "\n")
    layout["terminal"].update(Panel(log_text, title="[bold]System Terminal[/bold]", border_style="green"))
    
    # ATTACK SURFACE
    tree = Tree("[bold gold1]Attack Surface[/bold gold1]")
    
    # Tech Stack
    if 'tech' in data and data['tech']:
        # Ensure it's a list before slicing (fingerprint module uses set during scan)
        tech_list = list(data['tech'])
        tech_branch = tree.add(f"[bold cyan]Technology ({len(tech_list)})[/bold cyan]")
        for t in tech_list[:5]: tech_branch.add(escape(t))

    # Buckets
    if 's3' in data and data['s3']:
        s3_branch = tree.add(f"[bold yellow]S3 Buckets ({len(data['s3'])})[/bold yellow]")
        for b in data['s3'][:10]: s3_branch.add(escape(b))

    # Risks
    if 'risks' in data and data['risks']:
        risk_branch = tree.add(f"[bold red]Critical Risks ({len(data['risks'])})[/bold red]")
        for r in data['risks']: risk_branch.add(escape(r))
        
    if 'ports' in data and data['ports']:
        ports_branch = tree.add(f"[bold red]Open Ports ({len(data['ports'])})[/bold red]")
        for p in data['ports']:
            # Handle multiline (script output)
            lines = p.split('\n')
            first_line = lines[0]
            parts = first_line.split('|')
            if len(parts) > 2:
                # Escape the content parts
                port_id = escape(parts[0].strip())
                service = escape(parts[2].strip())
                
                label = f"[cyan]{port_id}[/cyan] : {service}"
                if len(parts) > 3 and parts[3].strip(): 
                    version = escape(parts[3].strip())
                    label += f" [dim]({version})[/dim]"
                
                node = ports_branch.add(label)
                if len(lines) > 1:
                    # Limit script output to 3 lines max
                    for script_line in lines[1:4]: 
                        node.add(f"[dim]{escape(script_line.strip())}[/dim]")
                    if len(lines) > 4:
                        node.add(f"[dim]... (+{len(lines)-4} more lines)[/dim]")
    
    if 'subdomains' in data and data['subdomains']:
        sub_branch = tree.add(f"[bold blue]Subdomains ({len(data['subdomains'])})[/bold blue]")
        for s in data['subdomains'][:10]: sub_branch.add(escape(s))

    if 'vhosts' in data and data['vhosts']:
        vhost_branch = tree.add(f"[bold yellow]VHosts ({len(data['vhosts'])})[/bold yellow]")
        for v in data['vhosts']: vhost_branch.add(escape(v))
    
    if 'dir_enum' in data and data['dir_enum']:
        dir_branch = tree.add(f"[bold magenta]Hidden Dirs ({len(data['dir_enum'])})[/bold magenta]")
        for d in data['dir_enum'][-10:]: dir_branch.add(escape(d))

    layout["surface"].update(Panel(tree, title="[bold]Live Findings[/bold]", border_style="gold1"))

    # FOOTER
    completed = list(module_status.values()).count("[green]Done[/green]")
    total_modules = 11
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
    import socket 
    
    # Shared Data
    scan_data = {'waf': 'Pending...', 'ports': [], 'subdomains': [], 'dir_enum': []}
    status_log = {"log_entries": []}
    
    module_status = {
        "WAF": "[dim]Waiting[/dim]", "Headers": "[dim]Waiting[/dim]", "SSL": "[dim]Waiting[/dim]",
        "Whois": "[dim]Waiting[/dim]", "DNS": "[dim]Waiting[/dim]", "Subdomains": "[dim]Waiting[/dim]",
        "Ports": "[dim]Waiting[/dim]", "DirEnum": "[dim]Waiting[/dim]", "Wayback": "[dim]Waiting[/dim]",
        "S3": "[dim]Waiting[/dim]", "Tech": "[dim]Waiting[/dim]"
    }
    
    def add_log(msg):
        if len(status_log["log_entries"]) > 100: status_log["log_entries"].pop(0)
        status_log["log_entries"].append(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}")

    async def engine_task():
        add_log(f"Initializing TitanRecon v2 on {target}...")
        try:
            client = TitanClient()
            await client.start()
        except Exception as e:
            add_log(f"CRITICAL INIT ERROR: {e}")
            return

        try:
            # 1. Critical & Tech
            module_status["WAF"] = "[yellow]Scanning[/yellow]"
            try: 
                await detect_waf(target, scan_data, add_log, client)
                module_status["WAF"] = "[green]Done[/green]"
            except Exception as e: 
                module_status["WAF"] = f"[red]Error: {e}[/red]"
                add_log(f"WAF CRASH: {e}")
            
            # Fingerprint (Tech)
            module_status["Tech"] = "[yellow]Scanning[/yellow]"
            await fingerprint_tech(target, scan_data, add_log, client)
            module_status["Tech"] = "[green]Done[/green]"

            # 2. Parallel Passive Recon
            add_log("Launching Recon Modules...")
            passive_tasks = []
            
            async def task_headers():
                try:
                    module_status["Headers"] = "[yellow]Fetching[/yellow]"
                    await headers(target, None, scan_data, client)
                    module_status["Headers"] = "[green]Done[/green]"
                except Exception as e: module_status["Headers"] = f"[red]Err[/red]"

            passive_tasks.append(task_headers())

            async def task_ssl():
                try:
                    module_status["SSL"] = "[yellow]Fetching[/yellow]"
                    await cert(hostname, 443, None, scan_data)
                    module_status["SSL"] = "[green]Done[/green]"
                except Exception as e: module_status["SSL"] = f"[red]Err[/red]"
            passive_tasks.append(task_ssl())

            async def task_whois():
                try:
                    module_status["Whois"] = "[yellow]Fetching[/yellow]"
                    await whois_lookup(hostname, "", None, None, scan_data)
                    module_status["Whois"] = "[green]Done[/green]"
                except Exception as e: module_status["Whois"] = f"[red]Err[/red]"
            passive_tasks.append(task_whois())

            async def task_subdomains():
                try:
                    module_status["Subdomains"] = "[yellow]Fetching[/yellow]"
                    await subdomains(hostname, 20, None, scan_data, None, logger=add_log, client=client)
                    module_status["Subdomains"] = "[green]Done[/green]"
                except Exception as e: module_status["Subdomains"] = f"[red]Err[/red]"
            passive_tasks.append(task_subdomains())

            async def task_wayback():
                 try:
                     module_status["Wayback"] = "[yellow]Archiving[/yellow]"
                     await timetravel(target, scan_data, None, client)
                     module_status["Wayback"] = "[green]Done[/green]"
                 except: module_status["Wayback"] = f"[red]Err[/red]"
            passive_tasks.append(task_wayback())
            
            # S3 Enumeration
            async def task_s3():
                try:
                    module_status["S3"] = "[yellow]Enumerating[/yellow]"
                    await s3_enum(target, scan_data, add_log, client)
                    module_status["S3"] = "[green]Done[/green]"
                except: module_status["S3"] = f"[red]Err[/red]"
            passive_tasks.append(task_s3())

            # Run Passive Safely
            await asyncio.gather(*passive_tasks, return_exceptions=True)
            add_log("[+] Recon Completed.")

            # 3. Active Scanning
            async def task_dns():
                try:
                    module_status["DNS"] = "[yellow]Bruteforcing[/yellow]"
                    await dnsrec(hostname, wordlist, None, scan_data, add_log)
                    module_status["DNS"] = "[green]Done[/green]"
                except Exception as e: 
                    module_status["DNS"] = f"[red]Err[/red]"
                    add_log(f"DNS Error: {e}")

            async def task_dir():
                try:
                    module_status["DirEnum"] = "[bold magenta]Enumerating[/bold magenta]"
                    await hammer(target, 10, 5, None, False, False, None, scan_data, "php", add_log, wordlist, client)
                    module_status["DirEnum"] = "[green]Done[/green]"
                except Exception as e:
                    module_status["DirEnum"] = f"[red]Err[/red]"
                    add_log(f"DirEnum Error: {e}")

            async def task_ports():
                if nmap_flags:
                    module_status["Ports"] = "[bold red]Scanning[/bold red]"
                    try:
                        loop = asyncio.get_running_loop()
                        try:
                            ip_info = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
                            ips = set()
                            for info in ip_info: ips.add(info[4][0])
                            if not ips: ips.add(hostname)
                            
                            scan_tasks = []
                            for ip in ips:
                                scan_tasks.append(scan(ip, None, scan_data, None, add_log, nmap_flags))
                            if scan_tasks: await asyncio.gather(*scan_tasks, return_exceptions=True)
                        except Exception as e:
                             await scan(hostname, None, scan_data, None, add_log, nmap_flags)
                        module_status["Ports"] = "[green]Done[/green]"
                    except Exception as e:
                         module_status["Ports"] = f"[red]Error[/red]"
                         add_log(f"[-] Portscan error: {e}")
                else:
                    module_status["Ports"] = "[dim]Skipped[/dim]"

            active_tasks = [task_dns(), task_dir(), task_ports()]
            await asyncio.gather(*active_tasks, return_exceptions=True)

            add_log("Scan Finished. Generating Report...")
            report_file = save_report(scan_data, target)
            add_log(f"Report saved: {report_file}")
            
            status_log["Finished"] = True
        finally:
            await client.close()

    loop = asyncio.get_running_loop()
    scan_task = loop.create_task(engine_task())
    
    start_time = datetime.datetime.now()
    
    with Live(create_layout(target, status_log, scan_data, module_status, start_time, 0), refresh_per_second=4, screen=True) as live:
        while not scan_task.done():
            live.update(create_layout(target, status_log, scan_data, module_status, start_time, 0))
            await asyncio.sleep(0.1)
        
    if scan_task.exception():
        console.print(f"[bold red]Scan Task Failed with error: {scan_task.exception()}[/bold red]")
            
    console.clear()
    console.print(Panel(f"[bold green]SCAN COMPLETED[/bold green]\n\nTarget: {target}\nWAF: {scan_data.get('waf')}\nPorts Found: {len(scan_data.get('ports', []))}\nFiles Saved: reports/", title="TitanRecon Summary", border_style="green"))

def run_titan():
    # Install Rich Traceback for pretty crash reports
    from rich.traceback import install
    install(show_locals=True)
    
    import asyncio
    # Removed uvloop intentionally to solve TUI freeze/crashing issues with subprocesses
    
    try:
        asyncio.run(run_titan_async())
    except KeyboardInterrupt:
        console.print("[red]\n[!] Aborted by user.[/red]")
    except Exception as e:
        console.print_exception()

if __name__ == "__main__":
    run_titan()