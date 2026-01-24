import whois
def whois_lookup(dom, suff, out_settings, proxy, data):
    try: data['whois'] = whois.whois(f"{dom}.{suff}")
    except: data['whois'] = "Lookup failed"