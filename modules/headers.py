import aiohttp
import asyncio

async def headers(target, out_settings, data):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target, timeout=5, ssl=False) as res:
                for k, v in res.headers.items():
                    data[k] = v
    except: pass