import aiohttp
import asyncio

async def detect_waf(target, data, logger):
    logger("[*] Checking for WAF...")
    signatures = {"Cloudflare": ["cf-ray", "cloudflare"], "AWS": ["x-amzn-requestid"], "Akamai": ["akamai"], "Incapsula": ["incap_ses"]}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target, timeout=10, ssl=False) as res:
                headers = {k.lower(): v for k, v in res.headers.items()}
                detected = []
                for waf, sigs in signatures.items():
                    for sig in sigs:
                        if sig in headers or sig in str(headers.values()): detected.append(waf); break
                if "cloudflare" in headers.get("server", "").lower(): detected.append("Cloudflare")
                
                if detected:
                    det_str = ', '.join(list(set(detected)))
                    data['waf'] = f"[bold red]Detected: {det_str}[/bold red]"
                    logger(f"[!] WAF DETECTED: {det_str}")
                else:
                    data['waf'] = "None Detected"
                    logger("[+] No standard WAF detected.")
    except Exception as e:
        data['waf'] = "Check Error"
        logger(f"[-] WAF Check Error: {str(e)}")