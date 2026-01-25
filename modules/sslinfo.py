import ssl
import asyncio

async def cert(hostname, ssl_port, out_settings, data):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        reader, writer = await asyncio.open_connection(hostname, 443, ssl=context)
        
        cert_bin = writer.get_extra_info('peercert')
        # get_extra_info returns the decoded dict if using ssl module, but sometimes binary?
        # Standard asyncio with ssl context returns the dict if obtained.
        # Actually proper way:
        cert = cert_bin 
        
        if cert:
            data['issuer'] = dict(x[0] for x in cert.get('issuer'))['commonName']
            data['subject'] = dict(x[0] for x in cert.get('subject'))['commonName']
            data['expires'] = cert.get('notAfter')
            
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        data['ssl_error'] = str(e)