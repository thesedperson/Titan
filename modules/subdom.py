import requests
def subdomains(hostname, tout, out_settings, data, conf_path):
    data['subdomains'] = []
    try:
        url = f"https://crt.sh/?q=%25.{hostname}&output=json"
        res = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
        if res.status_code == 200:
            subs = set()
            for item in res.json():
                name = item['name_value']
                if "\n" in name: 
                    for p in name.split("\n"): subs.add(p)
                else: subs.add(name)
            data['subdomains'] = sorted(list(subs))
    except: pass