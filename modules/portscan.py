import asyncio
import shutil
import re

async def scan(ip, out_settings, data, threads, logger=None, nmap_flags="-sV -T4 -F"):
    if not shutil.which("nmap"):
        if logger: logger("[-] Nmap binary not found!")
        return

    if ":" in ip:
        nmap_flags += " -6"
        
    cmd = f"nmap {nmap_flags} -Pn -v {ip}"
    if logger: logger(f"[*] Executing: {cmd}")
    data['ports'] = []
    
    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        while True:
            line = await process.stdout.readline()
            if not line: break
            
            line_str = line.decode('utf-8', errors='ignore').strip()
            if not line_str: continue

            if "Discovered open port" in line_str:
                try: 
                    clean_msg = line_str.split(" on ")[0]
                    if logger: logger(f"[+] {clean_msg}")
                except: pass
            
            if re.match(r"^\d+/(tcp|udp)", line_str) and "open" in line_str and "Discovered" not in line_str:
                try:
                    parts = re.split(r'\s+', line_str, maxsplit=3)
                    if len(parts) >= 3:
                        port = parts[0].split('/')[0]
                        entry = f"{ip}:{port} | {parts[1].upper()} | {parts[2]} | {parts[3] if len(parts)>3 else ''}"
                        data['ports'].append(entry)
                except: pass
        
        await process.wait()
        
        stderr = await process.stderr.read()
        if stderr and logger:
            err_msg = stderr.decode().strip()
            if err_msg: logger(f"[!] Nmap Stderr: {err_msg}")

    except Exception as e:
        if logger: logger(f"[-] Nmap Execution Error: {str(e)}")