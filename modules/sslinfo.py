import ssl, socket
def cert(hostname, ssl_port, out_settings, data):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False; context.verify_mode = ssl.CERT_NONE 
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
        conn.settimeout(3.0); conn.connect((hostname, 443))
        cert = conn.getpeercert(binary_form=False)
        data['issuer'] = dict(x[0] for x in cert.get('issuer'))['commonName']
        data['subject'] = dict(x[0] for x in cert.get('subject'))['commonName']
        data['expires'] = cert.get('notAfter')
        conn.close()
    except Exception as e: data['ssl_error'] = str(e)