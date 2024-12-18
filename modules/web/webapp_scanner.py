import aiohttp
import logging
from typing import Dict, List
from core.utils import RateLimit

class WebScanner:
    def __init__(self, target: str):
        self.target = target
        self.logger = logging.getLogger(__name__)
        self.rate_limiter = RateLimit(5)  # 5 requests per second
        self.headers = {
            'User-Agent': 'NexusGuard/1.0',
            'Accept': '*/*'
        }

    async def scan(self) -> Dict:
        """Perform web application security scan."""
        try:
            results = {
                'target': self.target,
                'vulnerabilities': [],
                'headers': {},
                'technologies': [],
                'status_code': None
            }

            async with aiohttp.ClientSession(headers=self.headers) as session:
                await self.rate_limiter.wait()
                async with session.get(f'https://{self.target}') as response:
                    results['status_code'] = response.status
                    results['headers'] = dict(response.headers)
                    
                    # Basic security header checks
                    security_headers = [
                        'Strict-Transport-Security',
                        'Content-Security-Policy',
                        'X-Frame-Options',
                        'X-Content-Type-Options',
                        'X-XSS-Protection'
                    ]
                    
                    for header in security_headers:
                        if header not in response.headers:
                            results['vulnerabilities'].append({
                                'type': f'Missing {header}',
                                'severity': 'MEDIUM',
                                'description': f'Security header {header} is not set'
                            })

            return results

        except Exception as e:
            self.logger.error(f"Error scanning {self.target}: {str(e)}")
            return {
                'target': self.target,
                'error': str(e)
            }

    async def check_common_vulnerabilities(self) -> List[Dict]:
        """Check for common web vulnerabilities."""
        vulnerabilities = []
        common_paths = [
            '/admin',
            '/phpinfo.php',
            '/.git/config',
            '/wp-admin',
            '/.env'
        ]

        async with aiohttp.ClientSession(headers=self.headers) as session:
            for path in common_paths:
                try:
                    await self.rate_limiter.wait()
                    url = f'https://{self.target}{path}'
                    async with session.get(url) as response:
                        if response.status != 404:
                            vulnerabilities.append({
                                'type': 'Sensitive Path Exposure',
                                'severity': 'HIGH',
                                'path': path,
                                'status_code': response.status
                            })
                except Exception:
                    continue

        return vulnerabilities
