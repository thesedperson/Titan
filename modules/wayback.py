import requests
def timetravel(target, data, out_settings):
    data['wayback'] = []
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url={target}/*&output=json&fl=original&collapse=urlkey"
        res = requests.get(url, timeout=10)
        if res.status_code == 200: data['wayback'] = [item[0] for item in res.json()[1:21]]
    except: pass