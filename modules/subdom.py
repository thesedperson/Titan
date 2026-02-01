import aiohttp
import asyncio

async def subdomains(hostname, tout, out_settings, data, conf_path, logger, client):
    data['subdomains'] = []
    
    # --- Source 1: crt.sh ---
    async def check_crt():
        try:
            url = f"https://crt.sh/?q=%25.{hostname}&output=json"
            async with client.get(url, timeout=20) as res:
                if res.status == 200:
                    content = await res.json()
                    for item in content:
                        name = item['name_value']
                        if "\n" in name: 
                            for p in name.split("\n"): data['subdomains'].append(p)
                        else: data['subdomains'].append(name)
        except: pass

    # --- Source 2: HackerTarget ---
    async def check_hackertarget():
        try:
             url = f"https://api.hackertarget.com/hostsearch/?q={hostname}"
             async with client.get(url, timeout=20) as res:
                 if res.status == 200:
                     text = await res.text()
                     for line in text.split('\n'):
                         if ',' in line:
                             sub = line.split(',')[0]
                             data['subdomains'].append(sub)
        except: pass

    # --- Source 3: AlienVault OTX ---
    async def check_alienvault():
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{hostname}/passive_dns"
            async with client.get(url, timeout=20) as res:
                if res.status == 200:
                    try:
                        js = await res.json()
                        for item in js.get('passive_dns', []):
                            data['subdomains'].append(item.get('hostname'))
                    except: pass
        except: pass

    if logger: logger("[*] Querying Passive Sources (crt.sh, HackerTarget, OTX)...")
    
    await asyncio.gather(check_crt(), check_hackertarget(), check_alienvault())
    
    # Deduplicate and Cleaner
    clean_subs = set()
    for s in data['subdomains']:
        s = s.strip().lower()
        if s.endswith(hostname) and '*' not in s:
            clean_subs.add(s)
            
    data['subdomains'] = sorted(list(clean_subs))
    if logger: logger(f"[+] Found {len(data['subdomains'])} unique subdomains.")