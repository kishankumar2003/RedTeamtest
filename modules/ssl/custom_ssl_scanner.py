import socket
import ssl
import OpenSSL
import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

@dataclass
class SSLInfo:
    hostname: str
    port: int
    version: str
    cipher: str
    cert_expires: datetime.datetime
    cert_issuer: str
    cert_subject: str
    cert_serial: str
    cert_fingerprint: str
    cert_version: int
    vulnerabilities: List[str]

class CustomSSLScanner:
    def __init__(self, hostname: str, port: int = 443, timeout: int = 10):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout
        self.vulnerabilities = []

    def get_server_info(self) -> Optional[SSLInfo]:
        """Get SSL/TLS information from the server."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert_binary = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_binary, default_backend())
                    
                    # Get OpenSSL certificate for additional info
                    cert_openssl = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_ASN1,
                        cert_binary
                    )

                    return SSLInfo(
                        hostname=self.hostname,
                        port=self.port,
                        version=ssock.version(),
                        cipher=ssock.cipher()[0],
                        cert_expires=cert.not_valid_after,
                        cert_issuer=self._get_issuer_str(cert),
                        cert_subject=self._get_subject_str(cert),
                        cert_serial=format(cert.serial_number, 'x'),
                        cert_fingerprint=self._get_fingerprint(cert_openssl),
                        cert_version=cert.version.value,
                        vulnerabilities=self._check_vulnerabilities(ssock, cert)
                    )
        except Exception as e:
            print(f"Error scanning {self.hostname}: {str(e)}")
            return None

    def _get_issuer_str(self, cert: x509.Certificate) -> str:
        """Get formatted issuer string."""
        return ', '.join([
            f"{oid._name}={value}" 
            for oid, value in cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        ])

    def _get_subject_str(self, cert: x509.Certificate) -> str:
        """Get formatted subject string."""
        return ', '.join([
            f"{oid._name}={value}" 
            for oid, value in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        ])

    def _get_fingerprint(self, cert: OpenSSL.crypto.X509) -> str:
        """Get certificate fingerprint."""
        return cert.digest('sha256').decode()

    def _check_vulnerabilities(self, ssock: ssl.SSLSocket, cert: x509.Certificate) -> List[str]:
        """Check for common SSL/TLS vulnerabilities."""
        vulnerabilities = []
        
        # Check certificate expiration
        if cert.not_valid_after < datetime.datetime.utcnow():
            vulnerabilities.append("Certificate has expired")
        
        # Check for weak protocols
        if ssock.version() in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
            vulnerabilities.append(f"Weak protocol version: {ssock.version()}")
        
        # Check signature algorithm
        sig_alg = cert.signature_algorithm_oid
        weak_algorithms = [
            '1.2.840.113549.1.1.4',  # md5WithRSAEncryption
            '1.2.840.113549.1.1.5',  # sha1WithRSAEncryption
        ]
        if sig_alg.dotted_string in weak_algorithms:
            vulnerabilities.append("Weak signature algorithm")
        
        # Check key size
        try:
            public_key = cert.public_key()
            key_size = public_key.key_size
            if key_size < 2048:
                vulnerabilities.append(f"Weak key size: {key_size} bits")
        except Exception:
            pass
        
        return vulnerabilities

    def scan(self) -> Dict:
        """Perform a full SSL/TLS scan."""
        info = self.get_server_info()
        if not info:
            return {
                "status": "error",
                "message": f"Could not scan {self.hostname}:{self.port}"
            }

        return {
            "status": "success",
            "hostname": info.hostname,
            "port": info.port,
            "ssl_info": {
                "version": info.version,
                "cipher": info.cipher,
            },
            "certificate": {
                "expires": info.cert_expires.isoformat(),
                "issuer": info.cert_issuer,
                "subject": info.cert_subject,
                "serial": info.cert_serial,
                "fingerprint": info.cert_fingerprint,
                "version": info.cert_version,
            },
            "vulnerabilities": info.vulnerabilities
        }

def scan_target(hostname: str, port: int = 443) -> Dict:
    """Convenience function to scan a target."""
    scanner = CustomSSLScanner(hostname, port)
    return scanner.scan()
