import requests
def detect_waf(target, data, logger):
    logger("[*] Checking for WAF...")
    signatures = {"Cloudflare": ["cf-ray", "cloudflare"], "AWS": ["x-amzn-requestid"], "Akamai": ["akamai"], "Incapsula": ["incap_ses"]}
    try:
        res = requests.get(target, timeout=5, verify=False)
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
    except: data['waf'] = "Check Error"