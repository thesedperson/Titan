import aiohttp
import asyncio

async def subdomains(hostname, tout, out_settings, data, conf_path, logger=None):
    data['subdomains'] = []
    try:
        url = f"https://crt.sh/?q=%25.{hostname}&output=json"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=20) as res:
                if res.status == 200:
                    content = await res.json()
                    subs = set()
                    for item in content:
                        name = item['name_value']
                        if "\n" in name: 
                            for p in name.split("\n"): subs.add(p)
                        else: subs.add(name)
                    data['subdomains'] = sorted(list(subs))
                    if logger: logger(f"[+] Found {len(data['subdomains'])} subdomains via crt.sh")
    except Exception as e:
        if logger: logger(f"[-] Subdomain Error: {str(e)}")
        pass