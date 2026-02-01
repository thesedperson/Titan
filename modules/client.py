import aiohttp
import asyncio
import random
import socket

class TitanClient:
    def __init__(self):
        # List of User-Agents to rotate
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        
        # Bypass Headers
        self.bypass_headers = {
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block',
            'X-Content-Type-Options': 'nosniff'
        }
        
        # We will initialize the session lazily or in start()
        self.session = None

    async def start(self):
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=15)
            # Force IPv4 to avoid "Name or service not known" on some IPv6-broken envs
            connector = aiohttp.TCPConnector(ssl=False, family=socket.AF_INET)
            self.session = aiohttp.ClientSession(timeout=timeout, connector=connector)

    async def close(self):
        if self.session:
            await self.session.close()

    def get_random_headers(self, target_url=None):
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'DNT': '1'
        }
        
        # IP Bypass Headers injection (randomized ip sometimes helpful, but static localhost often works for bypass)
        # Using 127.0.0.1 is common for bypassing "only allow local" rules
        bypass_ip = "127.0.0.1" 
        headers.update({
            'X-Originating-IP': bypass_ip,
            'X-Forwarded-For': bypass_ip,
            'X-Remote-IP': bypass_ip,
            'X-Remote-Addr': bypass_ip,
            'X-Client-IP': bypass_ip
        })
        
        if target_url:
            # Sometimes Referer/Origin helps
            pass
            
        return headers

    def get(self, url, **kwargs):
        """Wrapper for session.get with bypass headers"""
        if not self.session: raise RuntimeError("Client not started. Call await client.start() first.")
        
        # Merge headers
        req_headers = self.get_random_headers(url)
        if 'headers' in kwargs:
            req_headers.update(kwargs['headers'])
            del kwargs['headers']
            
        # Convert timeout int/float to ClientTimeout if present
        if 'timeout' in kwargs and isinstance(kwargs['timeout'], (int, float)):
             kwargs['timeout'] = aiohttp.ClientTimeout(total=kwargs['timeout'])
            
        return self.session.get(url, headers=req_headers, **kwargs)

    def head(self, url, **kwargs):
        """Wrapper for session.head"""
        if not self.session: raise RuntimeError("Client not started. Call await client.start() first.")
        
        req_headers = self.get_random_headers(url)
        if 'headers' in kwargs:
            req_headers.update(kwargs['headers'])
            del kwargs['headers']

        return self.session.head(url, headers=req_headers, **kwargs)

    def post(self, url, **kwargs):
        """Wrapper for session.post"""
        if not self.session: raise RuntimeError("Client not started. Call await client.start() first.")
        
        req_headers = self.get_random_headers(url)
        if 'headers' in kwargs:
            req_headers.update(kwargs['headers'])
            del kwargs['headers']

        return self.session.post(url, headers=req_headers, **kwargs)
