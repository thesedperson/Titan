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
    
    # --- 1. Nameserver Enumeration ---
    ns_servers = []
    try:
        ns_records = await resolver.query(hostname, 'NS')
        ns_servers = [r.host for r in ns_records]
        data['dns']['NS Records'] = ns_servers
        if logger: logger(f"[*] Found {len(ns_servers)} Nameservers: {', '.join(ns_servers)}")
    except:
        if logger: logger("[-] No Nameservers found (or query failed).")

    # --- 2. Zone Transfer (AXFR) ---
    # This usually requires 'dig' or 'host' command or dnspython. 
    # aiodns doesn't support AXFR natively (it's c-ares wrapper).
    # We use dnspython's async counterpart or just sync (since it's few requests).
    # Actually, let's use standard dnspython for this specific check, it's low volume.
    
    import dns.query
    import dns.zone
    import dns.resolver
    import dns.asyncquery
    
    if ns_servers:
        if logger: logger("[*] Checking for Zone Transfer (AXFR)...")
        for ns in ns_servers:
            try:
                # Resolve NS IP
                ns_ip = (await resolver.query(ns, 'A'))[0].host
                
                # Create a simple query
                # Use sync dnspython within executor to avoid blocking loop? 
                # Or just standard dns.asyncquery if available (recent dnspython). 
                # Only dnspython 2.3+ has async. Let's assume standard sync for safety in a thread.
                
                def check_axfr():
                    try:
                        z = dns.zone.from_xfr(dns.query.xfr(ns_ip, hostname, timeout=5))
                        return [n.to_text(omit_final_dot=True) for n in z.nodes.keys()]
                    except: return None
                
                # Run in thread
                loop = asyncio.get_running_loop()
                axfr_res = await loop.run_in_executor(None, check_axfr)
                
                if axfr_res:
                    data['dns'][f'AXFR_{ns}'] = axfr_res
                    if logger: logger(f"[!] CRITICAL: Zone Transfer successful on {ns}!")
                    # Add all found subdomains to data
                    for sub in axfr_res:
                        if sub != '@':
                            data['dns'][f"{sub}.{hostname}"] = ["Attributes from AXFR"]
            except: pass


    # --- 3. Subdomain Brute-force ---
    if logger: logger(f"[*] Starting Subdomain Brute Force...")

    import re
    # Valid subdomain regex
    sub_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')

    async def check_subdomain(sub):
        if not sub_pattern.match(sub): return None

        target = f"{sub}.{hostname}"
        async with sem:
            try:
                # Add explicit 5s timeout to prevent hanging on stalled queries
                result = await asyncio.wait_for(resolver.query(target, 'A'), timeout=5)
                ips = [r.host for r in result]
                return (target, ips)
            except Exception: 
                return None

    tasks = [check_subdomain(w) for w in words]
    
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