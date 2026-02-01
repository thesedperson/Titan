import whois
import asyncio

async def whois_lookup(dom, suff, out_settings, proxy, data):
    loop = asyncio.get_running_loop()
    try:
        data['whois'] = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: whois.whois(f"{dom}.{suff}")),
            timeout=10
        )
    except:
        data['whois'] = "Lookup failed"