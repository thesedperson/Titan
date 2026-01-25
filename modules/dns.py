import aiodns
import asyncio
import os

async def dnsrec(hostname, wordlist_path, out_settings, data, logger=None):
    if logger: logger(f"[*] Starting DNS Brute Force...")
    words = []
    if wordlist_path and os.path.exists(wordlist_path):
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
        except: pass
    
    if not words: words = ["www", "mail", "admin", "test", "dev", "shop", "api", "vpn"]

    resolver = aiodns.DNSResolver(loop=asyncio.get_running_loop())
    data['dns'] = {}
    
    sem = asyncio.Semaphore(100) # Limit concurrent queries

    async def check_subdomain(sub):
        target = f"{sub}.{hostname}"
        async with sem:
            try:
                result = await resolver.query(target, 'A')
                ips = [r.host for r in result]
                return (target, ips)
            except: 
                return None

    tasks = [check_subdomain(w) for w in words]
    # Process as they complete to update UI faster (?) or just gather all
    # Gather is simpler for result collection, but for huge lists, we might want to batch.
    # Given the previous code just waited, gather is fine for now, but to avoid 
    # memory issues with huge task lists, we should really chunk it.
    # However, for simplicity and compliance with "remove limit", let's use as_completed or chunking if the list is massive.
    # But for a direct replacement:
    
    for future in asyncio.as_completed(tasks):
        res = await future
        if res:
            sub, ips = res
            data['dns'][sub] = ips
            if logger: logger(f"[+] DNS Found: {sub}")

    # Check MX
    try:
        mx = await resolver.query(hostname, 'MX')
        data['dns']['MX Records'] = [r.host for r in mx]
    except: pass