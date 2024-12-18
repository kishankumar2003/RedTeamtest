import asyncio
import dns.resolver
import logging
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor
from core.utils import RateLimit

class SubdomainValidator:
    def __init__(self, max_concurrent: int = 50):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        self.rate_limiter = RateLimit(20)
        self.max_concurrent = max_concurrent
        self.logger = logging.getLogger(__name__)
        self.valid_subdomains: Set[str] = set()

    async def validate_subdomain(self, subdomain: str) -> Dict:
        """Validate a single subdomain using DNS lookups."""
        await self.rate_limiter.wait()
        try:
            # Try A record
            a_records = await self._resolve_record(subdomain, 'A')
            if a_records:
                self.valid_subdomains.add(subdomain)
                return {
                    'subdomain': subdomain,
                    'valid': True,
                    'a_records': a_records,
                    'status': 'active'
                }
            
            # Try CNAME if no A record
            cname_records = await self._resolve_record(subdomain, 'CNAME')
            if cname_records:
                self.valid_subdomains.add(subdomain)
                return {
                    'subdomain': subdomain,
                    'valid': True,
                    'cname_records': cname_records,
                    'status': 'active'
                }
            
            return {
                'subdomain': subdomain,
                'valid': False,
                'status': 'inactive'
            }
        except Exception as e:
            self.logger.debug(f"Error validating {subdomain}: {str(e)}")
            return {
                'subdomain': subdomain,
                'valid': False,
                'status': 'error',
                'error': str(e)
            }

    async def _resolve_record(self, domain: str, record_type: str) -> List[str]:
        """Resolve DNS records for a domain."""
        try:
            answers = self.resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]
        except Exception:
            return []

    async def validate_subdomains(self, subdomains: List[str]) -> List[Dict]:
        """Validate multiple subdomains concurrently."""
        tasks = []
        for subdomain in set(subdomains):  # Remove duplicates
            tasks.append(self.validate_subdomain(subdomain))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if not isinstance(r, Exception)]

    def get_valid_subdomains(self) -> Set[str]:
        """Return the set of validated subdomains."""
        return self.valid_subdomains
