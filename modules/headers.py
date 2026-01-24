import requests
def headers(target, out_settings, data):
    try:
        res = requests.get(target, timeout=5, verify=False)
        for k, v in res.headers.items():
            data[k] = v
    except: pass