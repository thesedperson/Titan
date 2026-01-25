import whois
import asyncio

async def whois_lookup(dom, suff, out_settings, proxy, data):
    loop = asyncio.get_running_loop()
    try:
        data['whois'] = await loop.run_in_executor(None, lambda: whois.whois(f"{dom}.{suff}"))
    except:
        data['whois'] = "Lookup failed"