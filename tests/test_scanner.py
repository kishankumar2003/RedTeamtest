import unittest
import asyncio
from modules.core.recursive_scanner import RecursiveScanner
from modules.dns.subdomain_validator import SubdomainValidator

class TestScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = RecursiveScanner(max_depth=1)
        self.validator = SubdomainValidator()

    def test_scanner_initialization(self):
        self.assertEqual(self.scanner.max_depth, 1)
        self.assertIsNotNone(self.scanner.rate_limiter)
        self.assertEqual(len(self.scanner.scanned_targets), 0)

    def test_validator_initialization(self):
        self.assertEqual(self.validator.max_concurrent, 50)
        self.assertIsNotNone(self.validator.resolver)
        self.assertEqual(len(self.validator.valid_subdomains), 0)

    async def test_subdomain_validation(self):
        result = await self.validator.validate_subdomain("www.google.com")
        self.assertTrue(result["valid"])
        self.assertEqual(result["status"], "active")

if __name__ == '__main__':
    unittest.main()
