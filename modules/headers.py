import aiohttp
import asyncio

async def headers(target, out_settings, data, client):
    try:
        async with client.get(target, timeout=5) as res:
            for k, v in res.headers.items():
                data[k] = v
    except: pass