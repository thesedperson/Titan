import os
import datetime

def save_report(data, target):
    # 1. Create Directory
    if not os.path.exists("reports"):
        os.makedirs("reports")
    
    # 2. Generate Filename
    # Handle cases where target might be weirdly formatted
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M')
    filepath = f"reports/TITAN_{domain}_{timestamp}.txt"
    
    # 3. Format the Data
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            # --- HEADER ---
            f.write("="*80 + "\n")
            f.write(f" TITAN RECON REPORT - v1.0 Community Edition\n")
            f.write("="*80 + "\n")
            f.write(f" Target      : {target}\n")
            f.write(f" Scan Date   : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f" WAF Status  : {data.get('waf', 'Unknown')}\n")
            f.write("="*80 + "\n\n")

            # --- SECTION: OPEN PORTS ---
            f.write("-" * 40 + "\n")
            f.write(f" [1] OPEN PORTS & SERVICES ({len(data.get('ports', []))})\n")
            f.write("-" * 40 + "\n")
            if data.get('ports'):
                f.write(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<15} {'VERSION'}\n")
                f.write("-" * 80 + "\n")
                for p in data['ports']:
                    try:
                        parts = p.split('|')
                        if len(parts) >= 3:
                            port = parts[0].strip()
                            state = parts[1].strip()
                            service = parts[2].strip()
                            version = parts[3].strip() if len(parts) > 3 else ""
                            f.write(f"{port:<10} {state:<10} {service:<15} {version}\n")
                    except:
                        f.write(f"{p}\n")
            else:
                f.write("No open ports found.\n")
            f.write("\n")

            # --- SECTION: SUBDOMAINS ---
            subs = list(data.get('subdomains', []))
            f.write("-" * 40 + "\n")
            f.write(f" [2] SUBDOMAINS FOUND ({len(subs)})\n")
            f.write("-" * 40 + "\n")
            if subs:
                for s in sorted(subs):
                    f.write(f" - {s}\n")
            else:
                f.write("No subdomains found.\n")
            f.write("\n")

            # --- SECTION: DIRECTORIES ---
            dirs = data.get('dir_enum', [])
            f.write("-" * 40 + "\n")
            f.write(f" [3] INTERESTING DIRECTORIES ({len(dirs)})\n")
            f.write("-" * 40 + "\n")
            if dirs:
                for d in dirs:
                    f.write(f" {d}\n")
            else:
                f.write("No interesting directories found.\n")
            f.write("\n")

            # --- SECTION: DNS RECORDS ---
            f.write("-" * 40 + "\n")
            f.write(" [4] DNS RECORDS\n")
            f.write("-" * 40 + "\n")
            if 'dns' in data and data['dns']:
                for host, records in data['dns'].items():
                    f.write(f" [HOST] {host}\n")
                    for r in records:
                        f.write(f"    -> {r}\n")
                    f.write("\n")
            else:
                f.write("No DNS records found.\n")
            f.write("\n")

            # --- SECTION: HTTP HEADERS ---
            f.write("-" * 40 + "\n")
            f.write(" [5] HTTP HEADERS\n")
            f.write("-" * 40 + "\n")
            for k, v in data.items():
                if k not in ['ports', 'subdomains', 'dir_enum', 'dns', 'waf', 'whois', 'crawler', 'wayback', 'ssl_error', 'issuer', 'subject', 'expires']:
                    f.write(f" {k:<25}: {v}\n")
            
            f.write("\n")
            f.write("="*80 + "\n")
            f.write(" END OF REPORT\n")
            f.write("="*80 + "\n")
            
        return filepath
    except Exception as e:
        print(f"Error saving report: {e}")
        return None