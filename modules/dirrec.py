import aiohttp
import asyncio
import os

async def hammer(target, threads, timeout, out_settings, proxy, redirect, header, data, ext, logger=None, wordlist_path=None):
    if logger: logger("[*] Starting Directory Enumeration...")
    words = []
    if wordlist_path and os.path.exists(wordlist_path):
        try:
            with open(wordlist_path, 'r', errors='ignore') as f: words = [line.strip() for line in f if line.strip()]
        except: pass
    if not words: words = ["admin", "login", "dashboard", "uploads", "images", "api", "config", "env"]

    data['dir_enum'] = []
    sem = asyncio.Semaphore(50) # Limit concurrent requests

    async with aiohttp.ClientSession() as session:
        async def check_dir(path):
            url = f"{target}/{path.lstrip('/')}"
            async with sem:
                try:
                    async with session.head(url, timeout=5, allow_redirects=False, ssl=False) as res:
                        if res.status in [200, 403]: return (url, res.status)
                except: pass
            return None

        tasks = [check_dir(w) for w in words]
        for future in asyncio.as_completed(tasks):
            result = await future
            if result:
                url, status = result
                data['dir_enum'].append(f"[{status}] /{url.split('/')[-1]}")
                if logger: logger(f"[+] Dir Found: /{url.split('/')[-1]} ({status})")