import subprocess, shutil, re
def scan(ip, out_settings, data, threads, logger=None, nmap_flags="-sV -T4 -F"):
    if not shutil.which("nmap"):
        if logger: logger("[-] Nmap binary not found!")
        return
    cmd = f"nmap {nmap_flags} -Pn -v {ip}"
    if logger: logger(f"[*] Executing: {cmd}")
    data['ports'] = []
    try:
        process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        for line in iter(process.stdout.readline, ''):
            line = line.strip()
            if not line: continue
            if "Discovered open port" in line:
                try: 
                    clean_msg = line.split(" on ")[0]
                    if logger: logger(f"[+] {clean_msg}")
                except: pass
            if re.match(r"^\d+/(tcp|udp)", line) and "open" in line and "Discovered" not in line:
                try:
                    parts = re.split(r'\s+', line, maxsplit=3)
                    if len(parts) >= 3:
                        entry = f"{parts[0].split('/')[0]} | {parts[1].upper()} | {parts[2]} | {parts[3] if len(parts)>3 else ''}"
                        data['ports'].append(entry)
                except: pass
    except Exception as e:
        if logger: logger(f"[-] Nmap Error: {str(e)}")