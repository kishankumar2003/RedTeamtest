import ssl
import socket
import logging
from typing import Dict, List
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class SSLScanner:
    def __init__(self, target: str, port: int = 443):
        self.target = target
        self.port = port
        self.logger = logging.getLogger(__name__)
        self.weak_ciphers = [
            'RC4',
            'DES',
            '3DES',
            'MD5',
            'NULL'
        ]

    def scan(self) -> Dict:
        """Perform SSL/TLS security scan."""
        try:
            results = {
                'target': self.target,
                'port': self.port,
                'certificate': {},
                'vulnerabilities': [],
                'protocols': [],
                'ciphers': []
            }

            # Get certificate information
            cert_info = self._get_certificate_info()
            results['certificate'] = cert_info

            # Check SSL/TLS protocols
            protocols = self._check_protocols()
            results['protocols'] = protocols

            # Check for vulnerabilities
            vulnerabilities = self._check_vulnerabilities(cert_info, protocols)
            results['vulnerabilities'] = vulnerabilities

            return results

        except Exception as e:
            self.logger.error(f"Error scanning {self.target}: {str(e)}")
            return {
                'target': self.target,
                'error': str(e)
            }

    def _get_certificate_info(self) -> Dict:
        """Get SSL certificate information."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cert_obj = x509.load_der_x509_certificate(cert, default_backend())
                    
                    return {
                        'subject': str(cert_obj.subject),
                        'issuer': str(cert_obj.issuer),
                        'version': cert_obj.version,
                        'not_before': cert_obj.not_valid_before.isoformat(),
                        'not_after': cert_obj.not_valid_after.isoformat(),
                        'serial_number': str(cert_obj.serial_number),
                        'signature_algorithm': cert_obj.signature_algorithm_oid._name
                    }
        except Exception as e:
            self.logger.error(f"Error getting certificate info: {str(e)}")
            return {}

    def _check_protocols(self) -> List[Dict]:
        """Check supported SSL/TLS protocols."""
        protocols = []
        test_protocols = [
            ssl.PROTOCOL_TLSv1,
            ssl.PROTOCOL_TLSv1_1,
            ssl.PROTOCOL_TLSv1_2,
            ssl.PROTOCOL_TLSv1_3
        ]

        for protocol in test_protocols:
            try:
                context = ssl.SSLContext(protocol)
                with socket.create_connection((self.target, self.port)) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        version = ssock.version()
                        protocols.append({
                            'name': version,
                            'supported': True
                        })
            except Exception:
                continue

        return protocols

    def _check_vulnerabilities(self, cert_info: Dict, protocols: List[Dict]) -> List[Dict]:
        """Check for SSL/TLS vulnerabilities."""
        vulnerabilities = []

        # Check certificate expiration
        if cert_info:
            not_after = datetime.fromisoformat(cert_info['not_after'])
            if not_after < datetime.now():
                vulnerabilities.append({
                    'type': 'Expired Certificate',
                    'severity': 'HIGH',
                    'description': f'Certificate expired on {not_after}'
                })

        # Check for weak protocols
        for protocol in protocols:
            if protocol['name'] in ['TLSv1.0', 'SSLv3', 'SSLv2']:
                vulnerabilities.append({
                    'type': 'Weak Protocol',
                    'severity': 'HIGH',
                    'description': f'Weak protocol {protocol["name"]} is supported'
                })

        return vulnerabilities
