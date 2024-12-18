import asyncio
import aiohttp
import logging
from typing import List, Dict, Optional
from pathlib import Path
from core.utils import RateLimit

class WebFuzzer:
    def __init__(self, target: str, rate_limit: int = 10):
        self.target = target
        self.logger = logging.getLogger(__name__)
        self.rate_limiter = RateLimit(rate_limit)
        self.session = None
        self.headers = {
            'User-Agent': 'NexusGuard/1.0',
            'Accept': '*/*'
        }

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(headers=self.headers)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def fuzz_directories(self, wordlist_path: str, extensions: List[str] = None) -> List[Dict]:
        """Fuzz directories using a wordlist."""
        if not Path(wordlist_path).exists():
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

        results = []
        extensions = extensions or ['.php', '.asp', '.aspx', '.jsp', '.html', '']

        async with aiohttp.ClientSession(headers=self.headers) as session:
            with open(wordlist_path, 'r') as f:
                words = [line.strip() for line in f if line.strip()]

            tasks = []
            for word in words:
                for ext in extensions:
                    path = f"{word}{ext}"
                    tasks.append(self.check_path(session, path))

            chunk_size = 50
            for i in range(0, len(tasks), chunk_size):
                chunk = tasks[i:i + chunk_size]
                chunk_results = await asyncio.gather(*chunk, return_exceptions=True)
                results.extend([r for r in chunk_results if r and not isinstance(r, Exception)])

        return results

    async def check_path(self, session: aiohttp.ClientSession, path: str) -> Optional[Dict]:
        """Check if a path exists on the target."""
        try:
            await self.rate_limiter.wait()
            url = f"https://{self.target}/{path.lstrip('/')}"
            
            async with session.get(url, allow_redirects=False) as response:
                if response.status != 404:
                    return {
                        'path': path,
                        'url': url,
                        'status': response.status,
                        'content_type': response.headers.get('content-type', ''),
                        'content_length': response.headers.get('content-length', ''),
                        'interesting': self._is_interesting(response)
                    }
        except Exception as e:
            self.logger.debug(f"Error checking {path}: {str(e)}")
        return None

    def _is_interesting(self, response: aiohttp.ClientResponse) -> bool:
        """Determine if a response is interesting based on various factors."""
        interesting_indicators = [
            response.status in [200, 301, 302, 401, 403],
            int(response.headers.get('content-length', 0)) > 500,
            any(tech in response.headers.get('server', '').lower() 
                for tech in ['apache', 'nginx', 'iis', 'tomcat'])
        ]
        return any(interesting_indicators)

    async def fuzz_parameters(self, endpoint: str, wordlist_path: str) -> List[Dict]:
        """Fuzz parameters on a specific endpoint."""
        results = []
        
        if not Path(wordlist_path).exists():
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

        async with aiohttp.ClientSession(headers=self.headers) as session:
            with open(wordlist_path, 'r') as f:
                params = [line.strip() for line in f if line.strip()]

            tasks = []
            for param in params:
                tasks.append(self.check_parameter(session, endpoint, param))

            chunk_size = 50
            for i in range(0, len(tasks), chunk_size):
                chunk = tasks[i:i + chunk_size]
                chunk_results = await asyncio.gather(*chunk, return_exceptions=True)
                results.extend([r for r in chunk_results if r and not isinstance(r, Exception)])

        return results

    async def check_parameter(self, session: aiohttp.ClientSession, endpoint: str, param: str) -> Optional[Dict]:
        """Check if a parameter exists and is processed by the endpoint."""
        try:
            await self.rate_limiter.wait()
            url = f"https://{self.target}/{endpoint.lstrip('/')}"
            test_values = ['1', 'true', 'test', "' OR '1'='1"]
            
            results = []
            for value in test_values:
                params = {param: value}
                async with session.get(url, params=params, allow_redirects=False) as response:
                    content_length = int(response.headers.get('content-length', 0))
                    results.append({
                        'value': value,
                        'status': response.status,
                        'length': content_length
                    })

            # Analyze results for interesting behavior
            if self._analyze_param_results(results):
                return {
                    'parameter': param,
                    'endpoint': endpoint,
                    'interesting': True,
                    'results': results
                }
        except Exception as e:
            self.logger.debug(f"Error checking parameter {param}: {str(e)}")
        return None

    def _analyze_param_results(self, results: List[Dict]) -> bool:
        """Analyze parameter test results for interesting behavior."""
        status_codes = set(r['status'] for r in results)
        lengths = set(r['length'] for r in results)
        
        interesting_indicators = [
            len(status_codes) > 1,  # Different responses
            len(lengths) > 1,       # Different content lengths
            any(s in status_codes for s in [200, 302, 401, 403, 500]),  # Interesting status codes
            max(lengths) - min(lengths) > 100  # Significant content length difference
        ]
        return any(interesting_indicators)
