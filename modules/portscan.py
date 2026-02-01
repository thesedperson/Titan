import asyncio
import shutil
import re

async def scan(ip, out_settings, data, threads, logger=None, nmap_flags="-sV -T4 -F"):
    if not shutil.which("nmap"):
        if logger: logger("[-] Nmap binary not found!")
        return

    if ":" in ip:
        nmap_flags += " -6"
        
    # Speed optimizations
    nmap_flags += " --min-rate 1000 --max-retries 2"

    cmd = f"nmap {nmap_flags} -Pn -v {ip}"
    if logger: logger(f"[*] Executing Nmap: {cmd}")
    else: print(f"[DEBUG] Executing Nmap: {cmd}") # Fallback for debug
    data['ports'] = []
    
    try:
        # Use simple exec to avoid shell issues, split flags
        args = ["nmap"] + nmap_flags.split() + ["-Pn", "-v", ip]
        
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        while True:
            # Read line by line asynchronously
            try:
                line = await asyncio.wait_for(process.stdout.readline(), timeout=300) # 5 min timeout per line to detect hangs
            except asyncio.TimeoutError:
                if logger: logger("[!] Nmap output timed out. Killing...")
                process.kill()
                break
                
            if not line: break
            
            line_str = line.decode('utf-8', errors='ignore').strip()
            if not line_str: continue

            # Forward Progress/Status lines
            if logger and ("Scanning" in line_str or "Completed" in line_str or "Timing" in line_str):
                 logger(f"[*] Nmap: {line_str}")
            
            # Debug all lines if needed (can be noisy, so keep it selective or use the fallback print)
            # print(f"[NM] {line_str}") 

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
                        # IP:PORT | STATUS | SERVICE | VERSION
                        version_info = parts[3] if len(parts) > 3 else ""
                        entry = f"{ip}:{port} | {parts[1].upper()} | {parts[2]} | {version_info}"
                        data['ports'].append(entry)
                except: pass
            
            # Capture Script Output (lines starting with | or |_)
            elif (line_str.startswith('|') or line_str.startswith('|_')) and data['ports']:
                 try:
                     data['ports'][-1] += f"\n   {line_str}"
                 except: pass
        
        await process.wait()
        
        # Ensure we read any remaining stderr
        stderr = await process.stderr.read()
        if stderr and logger:
            err_msg = stderr.decode().strip()
            # Only log critical errors to avoid noise
            if "Failed to resolve" in err_msg or "error" in err_msg.lower():
                 if logger: logger(f"[!] Nmap Error: {err_msg}")

    except Exception as e:
        if logger: logger(f"[-] Nmap Execution Error: {str(e)}")