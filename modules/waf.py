import aiohttp
import asyncio

async def detect_waf(target, data, logger, client):
    logger("[*] Checking for WAF...")
    signatures = {"Cloudflare": ["cf-ray", "cloudflare"], "AWS": ["x-amzn-requestid"], "Akamai": ["akamai"], "Incapsula": ["incap_ses"]}
    try:
        # First request: Standard
        async with client.get(target, timeout=10) as res:
            headers = {k.lower(): v for k, v in res.headers.items()}
            detected = []
            for waf, sigs in signatures.items():
                for sig in sigs:
                    if sig in headers or sig in str(headers.values()): detected.append(waf); break
            
            if "cloudflare" in headers.get("server", "").lower(): detected.append("Cloudflare")
            
            if detected:
                det_str = ', '.join(list(set(detected)))
                data['waf'] = f"Detected: {det_str}"
                logger(f"[!] WAF DETECTED: {det_str}")
            else:
                data['waf'] = "None Detected"
                logger("[+] No standard WAF detected.")
                
            # Basic Bypass Check (if 403)
            # Basic Bypass Check (if 403)
            if res.status == 403:
                logger("[!] 403 Forbidden detected. Attempting advanced bypass...")
                
                bypass_headers_list = [
                    {'Referer': target},
                    {'X-Rewrite-URL': target},
                    {'X-Original-URL': target},
                    {'X-Forwarded-Host': 'localhost'},
                ]
                
                bypassed = False
                for i, b_head in enumerate(bypass_headers_list):
                    try:
                        if logger: logger(f"[-] WAF Bypass Attempt {i+1}...")
                        async with client.get(target, headers=b_head, timeout=5) as retrying:
                            if retrying.status == 200:
                                logger(f"[+] WAF Bypass Successful with {list(b_head.keys())[0]}!")
                                data['waf'] += " (Bypassed)"
                                bypassed = True
                                break
                    except: pass
                
                if not bypassed:
                    # Try rotating UA one last time
                    try:
                         if logger: logger("[-] WAF Bypass Attempt (UA Rotate)...")
                         async with client.get(target, timeout=5) as retrying: 
                            if retrying.status == 200:
                                logger("[+] WAF Bypass Successful with UA Rotation!")
                                data['waf'] += " (Bypassed)"
                                bypassed = True
                    except: pass
                    
                if not bypassed:
                    logger("[-] Bypass attempts failed.")

    except Exception as e:
        data['waf'] = "Check Error"
        logger(f"[-] WAF Check Error: {str(e)}")