import asyncio
import random

async def s3_enum(target, data, logger=None, client=None):
    if logger: logger("[*] Starting S3 Bucket Enumeration...")
    
    # Extract keyword from domain
    from urllib.parse import urlparse
    parsed = urlparse(target)
    domain_parts = parsed.netloc.split('.')
    keyword = domain_parts[-2] if len(domain_parts) >= 2 else domain_parts[0]
    
    # Permutations (Gobuster style + Common)
    permutations = [
        keyword,
        f"{keyword}.com",
        f"{keyword}-assets",
        f"{keyword}-dev",
        f"{keyword}-backup",
        f"{keyword}-public",
        f"{keyword}-static",
        f"{keyword}-staging",
        f"{keyword}-test",
        f"{keyword}-logs",
        f"assets-{keyword}",
        f"dev-{keyword}",
        f"backup-{keyword}"
    ]
    
    data['s3'] = []
    
    # Semaphore
    sem = asyncio.Semaphore(50)
    
    async def check_bucket(name):
        # AWS S3 URL format
        url = f"http://{name}.s3.amazonaws.com"
        async with sem:
            try:
                # We interpret 200 (Open) and 403 (Protected but exists) as valid buckets
                async with client.head(url, timeout=3) as res:
                    if res.status == 200:
                        data['s3'].append(f"[OPEN] {url}")
                        if logger: logger(f"[+] Found OPEN Bucket: {name}")
                    elif res.status == 403:
                         data['s3'].append(f"[PROTECTED] {url}")
                         if logger: logger(f"[+] Found Protected Bucket: {name}")
            except: pass

    tasks = [check_bucket(p) for p in permutations]
    
    # Run with limited concurrency
    await asyncio.gather(*tasks, return_exceptions=True)
