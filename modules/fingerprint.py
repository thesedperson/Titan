import asyncio
import re

async def fingerprint_tech(target, data, logger=None, client=None):
    if logger: logger("[*] Fingerprinting Technology & Risks...")
    data['tech'] = set()
    data['risks'] = []
    
    # 1. Header & Main Body Analysis
    try:
        if logger: logger("[-] Fingerprint: Requesting main page...")
        async with client.get(target, timeout=10, allow_redirects=True) as res:
            if logger: logger("[-] Fingerprint: Got headers. Analyzing...")
            # Headers
            if 'Server' in res.headers: 
                data['tech'].add(f"Server: {res.headers['Server']}")
            if 'X-Powered-By' in res.headers: 
                data['tech'].add(f"PoweredBy: {res.headers['X-Powered-By']}")
            if 'X-AspNet-Version' in res.headers:
                data['tech'].add(f"AspNet: {res.headers['X-AspNet-Version']}")
            
            # Cookies (Simple checks)
            for cookie in res.cookies.keys():
                if 'JSESSIONID' in cookie: data['tech'].add("Java/J2EE")
                if 'PHPSESSID' in cookie: data['tech'].add("PHP")
                if 'csrftoken' in cookie: data['tech'].add("Django/Python")
                if 'laravel' in cookie: data['tech'].add("Laravel")

            # Body Analysis (Limit to 1MB to prevent hanging on large files)
            if logger: logger("[-] Fingerprint: Reading body...")
            try:
                raw_body = await res.content.read(1024 * 1024) # 1MB limit
                body = raw_body.decode(errors='ignore')
            except: body = ""
            if logger: logger("[-] Fingerprint: Body read complete.")
            
            generator = re.search(r'<meta name="generator" content="(.*?)"', body, re.I)
            if generator:
                data['tech'].add(f"Generator: {generator.group(1)}")
                
            # signatures
            if "wp-content" in body: data['tech'].add("WordPress")
            if "drupal" in body: data['tech'].add("Drupal")
            if "joomla" in body: data['tech'].add("Joomla")
            if "bootstrap" in body: data['tech'].add("Bootstrap")
            if "jquery" in body: data['tech'].add("jQuery")
            
    except Exception as e:
         if logger: logger(f"[-] Fingerprint Main Error: {e}")
    
    # 2. Risk Files Check (robots, git, sitemap)
    if logger: logger("[-] Fingerprint: Checking risk files...")
    risk_files = [
        "robots.txt", 
        "sitemap.xml", 
        ".git/HEAD", 
        ".env", 
        "backup.zip", 
        "ds_store"
    ]
    
    async def check_file(filename):
        url = f"{target}/{filename}"
        try:
             # if logger: logger(f"[-] Checking {filename}...")
             async with client.get(url, timeout=5, allow_redirects=False) as res:
                  if res.status == 200:
                      # Verify .git
                      if filename == ".git/HEAD" and "ref:" not in (await res.text()):
                          return
                      
                      data['risks'].append(f"/{filename}")
                      if logger: logger(f"[!] Risk File Found: /{filename}")
                      
                      # Parse robots.txt for hidden paths
                      if filename == "robots.txt":
                           body = await res.text()
                           disallowed = re.findall(r"Disallow: (.*)", body)
                           for d in disallowed:
                               clean = d.strip()
                               if clean and clean != "/":
                                   data['tech'].add(f"Robots: {clean}")

        except: pass

    tasks = [check_file(f) for f in risk_files]
    await asyncio.gather(*tasks, return_exceptions=True)
    if logger: logger("[-] Fingerprint: Risk checks done.")

    # Convert set to list for reporting
    data['tech'] = list(data['tech'])
