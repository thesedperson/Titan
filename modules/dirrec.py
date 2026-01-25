import aiohttp
import asyncio
import os

async def hammer(target, threads, timeout, out_settings, proxy, redirect, header, data, ext, logger, wordlist_path, client):
    if logger: logger("[*] Starting Directory Enumeration...")
    words = []
    if wordlist_path and os.path.exists(wordlist_path):
        try:
            with open(wordlist_path, 'r', errors='ignore') as f: words = [line.strip() for line in f if line.strip()]
        except: pass
    if not words: words = ["admin", "login", "dashboard", "uploads", "images", "api", "config", "env"]

    import random
    import string

    async def calibrate(client, target):
        # Generate random path
        rand_path = "".join(random.choices(string.ascii_lowercase, k=12))
        url = f"{target}/{rand_path}"
        try:
            async with client.head(url, timeout=5, allow_redirects=False) as res:
                return res.status
        except:
            return None

    # Calibrate first
    if logger: logger("[*] Calibrating directory detection...")
    baseline_status = await calibrate(client, target)
    if logger: logger(f"[*] Baseline status for random path: {baseline_status}")

    ignored_statuses = []
    if baseline_status in [200, 403]:
        ignored_statuses.append(baseline_status)
        if logger: logger(f"[!] Warning: Target returns {baseline_status} for random paths. Ignoring {baseline_status} to prevent false positives.")

    sem = asyncio.Semaphore(50) # Limit concurrent requests

    async def check_dir(path):
        url = f"{target}/{path.lstrip('/')}"
        async with sem:
            try:
                # Use client.head
                async with client.head(url, timeout=5, allow_redirects=False) as res:
                    if res.status in [200, 403]: 
                        # Filter out ignored statuses (baseline matches)
                        if res.status in ignored_statuses:
                            return None
                        return (url, res.status)
            except: pass
        return None

    tasks = [check_dir(w) for w in words]
    for future in asyncio.as_completed(tasks):
        result = await future
        if result:
            url, status = result
            data['dir_enum'].append(f"[{status}] /{url.split('/')[-1]}")
            if logger: logger(f"[+] Dir Found: /{url.split('/')[-1]} ({status})")