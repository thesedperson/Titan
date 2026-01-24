import dns.resolver, concurrent.futures, os
def dnsrec(hostname, wordlist_path, out_settings, data, logger=None):
    if logger: logger(f"[*] Starting DNS Brute Force...")
    words = []
    if wordlist_path and os.path.exists(wordlist_path):
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f.readlines()[:2000]]
        except: pass
    if not words: words = ["www", "mail", "admin", "test", "dev", "shop", "api", "vpn"]

    resolver = dns.resolver.Resolver(); resolver.timeout = 1; resolver.lifetime = 1
    data['dns'] = {}

    def check_subdomain(sub):
        try:
            answers = resolver.resolve(f"{sub}.{hostname}", 'A')
            return (f"{sub}.{hostname}", [r.to_text() for r in answers])
        except: return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_subdomain, w): w for w in words}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                sub, ips = result
                data['dns'][sub] = ips
                if logger: logger(f"[+] DNS Found: {sub}")
    try:
        mx = resolver.resolve(hostname, 'MX')
        data['dns']['MX Records'] = [r.to_text() for r in mx]
    except: pass