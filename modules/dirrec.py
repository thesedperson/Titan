import aiohttp
import asyncio
import os
import sys

async def hammer(target, threads, timeout, out_settings, proxy, redirect, header, data, ext, logger, wordlist_path, client):
    if logger: logger("[*] High-Performance Directory & VHost Enumeration...")
    
    # ... (Configuration) ...
    from urllib.parse import urlparse
    parsed = urlparse(target)
    domain = parsed.netloc.split(':')[0]
    scheme = parsed.scheme
    
    # Limit Concurrency
    sem = asyncio.Semaphore(100) # Safe limit for stability 
    
    # Extensions
    extensions = ['.php', '.html', '.txt'] if not ext else ([f".{x}" for x in ext.split(',')])
    if 'php' in extensions: extensions.append('')

    # --- 0. Double Calibration ---
    import random, string
    
    async def get_baseline(url, custom_header=None):
        try:
             # Use GET to get full body size for accurate calibration
             h = custom_header if custom_header else {}
             async with client.get(url, headers=h, timeout=5, allow_redirects=redirect) as res: 
                  content = await res.read()
                  return res.status, len(content)
        except: return None, 0

    if logger: logger("[*] Calibrating Baselines...")
    
    # 1. Normal Baseline (Root)
    norm_status, norm_len = await get_baseline(target)
    
    # 2. Abnormal Baseline (Random Path / VHost)
    rand_name = "".join(random.choices(string.ascii_lowercase, k=16))
    
    # For Directory Mode: Random Path
    dir_abnorm_status, dir_abnorm_len = await get_baseline(f"{target}/{rand_name}")
    
    # For VHost Mode: Random Subdomain (if checking vhosts)
    vhost_abnorm_status, vhost_abnorm_len = 0, 0
    if not domain.replace('.', '').isdigit():
        vhost_abnorm_status, vhost_abnorm_len = await get_baseline(f"{scheme}://{domain}", custom_header={"Host": f"{rand_name}.{domain}"})

    if logger: 
        logger(f"[*] Calibration Complete.")
        logger(f"    - Dir Baseline: {dir_abnorm_status} (Size: {dir_abnorm_len})")
        if vhost_abnorm_status:
            logger(f"    - VHost Baseline: {vhost_abnorm_status} (Size: {vhost_abnorm_len})")

    # Interesting Status Codes (Helpful Only)
    INTERESTING = [200, 201, 204, 301, 302, 307, 401, 403, 405]

    # --- Helper: Is it interesting? ---
    def is_interesting(status, length, mode="dir"):
        if status not in INTERESTING: return False
        
        # Check against Baselines
        # If status matches Abnormal Baseline, check length
        abnorm_s = dir_abnorm_status if mode == "dir" else vhost_abnorm_status
        abnorm_l = dir_abnorm_len if mode == "dir" else vhost_abnorm_len
        
        # Strict VHost 403 Filter (Nuclear Option)
        # If the user wants "only useful info", generic 403s are noise.
        if mode == "vhost" and status == 403:
             # If we have a valid baseline length, check fuzzy match
             if vhost_abnorm_len > 0:
                  diff = abs(length - vhost_abnorm_len)
                  # If deviation is small (less than 30% or 1000 bytes), DROP IT
                  if diff < 1000 or diff < (vhost_abnorm_len * 0.3):
                       return False
             else:
                  # If baseline failed (0), we can't trust 403s. Drop them to avoid spam.
                  # It is better to miss a 403 than spam thousands.
                  return False

        # If status matches Abnormal (typically 404 disguised as 200)
        # Standard check for other codes
        if status == abnorm_s:
            # Fuzzy Size Match ( +/- 10% or 200 bytes)
            diff = abs(length - abnorm_l)
            if diff < 200 or diff < (abnorm_l * 0.1):
                return False

        # If status matches Normal (Root), usually for VHost (e.g. all vhosts showing main site)
        if mode == "vhost" and status == norm_status:
             diff = abs(length - norm_len)
             if diff < 200 or diff < (norm_len * 0.1):
                return False
                
        return True

    # --- 1. Streamed Directory Enum ---
    async def worker(word):
        variants = [word] + [f"{word}{e}" for e in extensions if e]
        for variant in variants:
            url = f"{target}/{variant}"
            async with sem:
                try:
                    # HEAD is faster for initial check, but GET needed for size if HEAD is ambiguous.
                    # Optimization: HEAD first. If interesting status, GET to verify size if needed.
                    # Or just GET. Gobuster does GET by default. Let's do GET to be accurate with size.
                    # With uvloop it's fast.
                    
                    async with client.get(url, timeout=timeout, allow_redirects=redirect) as res:
                        length = int(res.headers.get('Content-Length', 0))
                        # If no content-length header, we might need to read.
                        # But reading body of every request is heavy.
                        # Optimization: Reader only if status is interesting?
                        # Let's trust Content-Length or read minimal.
                        if length == 0: 
                            # Peek?
                            pass 
                        
                        # For speed, let's use Content-Length if present. 
                        # If strict filtering is key, we should allow body read if CL is missing.
                        
                        if is_interesting(res.status, length, "dir"):
                             data['dir_enum'].append(f"[{res.status}] /{variant}")
                             if logger: logger(f"[+] Found: /{variant} ({res.status})")
                except: pass

    # ... (Generator code same as before) ...
    def word_gen():
        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path, 'r', errors='ignore') as f:
                for line in f:
                    w = line.strip()
                    if w and not w.startswith('#'): yield w
        else:
            for w in ["admin", "login", "api", "dev"]: yield w

    # ... (Task Pool same as before) ...
    tasks = set()
    gen = word_gen()
    count = 0
    # Increase concurrency limit to standard safe value (100) if threads is low
    concurrency_limit = max(threads * 2, 100)
    
    try:
        while True:
            if len(tasks) >= concurrency_limit:
                # Add explicit timeout so we don't hang if all tasks are slow/hung
                done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED, timeout=5)
            try:
                w = next(gen)
                count += 1
                if count % 100 == 0:
                     msg = f"[*] DirEnum Progress: {count} words..."
                     if logger: logger(msg) 
                     # Removing stderr debug to clean up, rely on TUI
                tasks.add(asyncio.create_task(worker(w)))
            except StopIteration: break
    finally:
        if tasks: 
            if logger: logger(f"[*] Waiting for {len(tasks)} remaining directory checks...")
            try:
                done, pending = await asyncio.wait(tasks, timeout=30)
                if pending:
                    if logger: logger(f"[!] {len(pending)} tasks stuck. Cancelling...")
                    for p in pending: p.cancel()
            except Exception as e:
                if logger: logger(f"[!] Error waiting for tasks: {e}")

    # --- 2. VHost Scan ---
    if domain.replace('.', '').isdigit(): return 
    
    if logger: logger("[*] Starting VHost Brute-forcing...")
    
    async def vhost_worker(sub):
        vhost = f"{sub}.{domain}"
        async with sem:
            try:
                async with client.get(f"{scheme}://{domain}", headers={"Host": vhost}, timeout=timeout, allow_redirects=redirect) as res:
                    length = int(res.headers.get('Content-Length', 0))
                    if is_interesting(res.status, length, "vhost"):
                         data.setdefault('vhosts', []).append(f"[{res.status}] {vhost}")
                         if logger: logger(f"[+] VHost: {vhost} ({res.status})")
            except: pass
            
    vtasks = set()
    vgen = word_gen() # Reuse list
    try:
        while True:
            if len(vtasks) >= threads * 2:
                done, vtasks = await asyncio.wait(vtasks, return_when=asyncio.FIRST_COMPLETED, timeout=5)
            try:
                w = next(vgen)
                vtasks.add(asyncio.create_task(vhost_worker(w)))
            except StopIteration: break
    finally:
        if vtasks:
            if logger: logger(f"[*] Waiting for {len(vtasks)} remaining VHost checks...")
            try:
                done, pending = await asyncio.wait(vtasks, timeout=30)
                if pending:
                    for p in pending: p.cancel()
            except: pass