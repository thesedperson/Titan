import requests, concurrent.futures, os
def hammer(target, threads, timeout, out_settings, proxy, redirect, header, data, ext, logger=None, wordlist_path=None):
    if logger: logger("[*] Starting Directory Enumeration...")
    words = []
    if wordlist_path and os.path.exists(wordlist_path):
        try:
            with open(wordlist_path, 'r', errors='ignore') as f: words = [line.strip() for line in f.readlines()[:2000]]
        except: pass
    if not words: words = ["admin", "login", "dashboard", "uploads", "images", "api", "config", "env"]

    data['dir_enum'] = []
    def check_dir(path):
        url = f"{target}/{path.lstrip('/')}"
        try:
            res = requests.head(url, timeout=3, allow_redirects=False)
            if res.status_code in [200, 403]: return (url, res.status_code)
        except: pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_dir, w): w for w in words}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                url, status = result
                data['dir_enum'].append(f"[{status}] /{url.split('/')[-1]}")
                if logger: logger(f"[+] Dir Found: /{url.split('/')[-1]} ({status})")