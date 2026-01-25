import aiohttp
import asyncio

async def timetravel(target, data, out_settings):
    data['wayback'] = []
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url={target}/*&output=json&fl=original&collapse=urlkey"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as res:
                if res.status == 200: 
                    content = await res.json()
                    data['wayback'] = [item[0] for item in content[1:21]]
    except Exception: pass