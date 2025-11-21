"""
SSL Certificate Helper for Testing

⚠️  WARNING: THIS IS TEST-ONLY CODE ⚠️
This module disables SSL/TLS hostname verification and certificate validation
for testing purposes with self-signed certificates.

DO NOT USE IN PRODUCTION CODE.

Generates and caches self-signed SSL certificates for use in test servers.
This allows tests to use HTTPS without requiring real certificates.
"""

import ssl
import os
import tempfile
import ipaddress
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime


class TestSSLHelper:
    """Helper class to generate and manage SSL certificates for testing."""
    
    _cert_cache = {}
    
    @classmethod
    def get_ssl_context(cls, for_server=True, for_client=False):
        """
        Get an SSL context for testing.
        
        ⚠️  WARNING: TEST-ONLY - Disables certificate verification for self-signed certs.
        DO NOT USE IN PRODUCTION.
        
        Args:
            for_server: If True, returns a server SSL context with certificate
            for_client: If True, returns a client SSL context that accepts self-signed certs
            
        Returns:
            ssl.SSLContext configured appropriately for testing
        """
        if for_client:
            # Client context that accepts self-signed certificates for testing
            # SECURITY NOTE: This is TEST-ONLY code for local development with self-signed certificates.
            # Production code MUST use proper certificate verification.
            # Using TLS 1.2+ with secure defaults from create_default_context()
            context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=None)  # NOSONAR - Test-only: Hostname verification disabled below for self-signed certs
            # Disable hostname verification for self-signed test certificates
            context.check_hostname = False  # NOSONAR - Test-only: Required for self-signed test certs
            context.verify_mode = ssl.CERT_NONE  # NOSONAR - Test-only: Accepts self-signed test certs
            # Ensure minimum TLS 1.2 for security even in tests
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            return context
        
        if for_server:
            # Server context with self-signed certificate
            cert_file, key_file = cls._get_or_create_certificate()
            # PROTOCOL_TLS_SERVER uses secure defaults in Python 3.10+
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # noqa: S502  # NOSONAR - Modern TLS protocol
            context.load_cert_chain(cert_file, key_file)
            return context
        
        return None
    
    @classmethod
    def _get_or_create_certificate(cls):
        """
        Get or create a self-signed certificate for localhost.
        
        Returns:
            Tuple of (cert_file_path, key_file_path)
        """
        cache_key = "localhost_cert"
        
        if cache_key in cls._cert_cache:
            return cls._cert_cache[cache_key]
        
        # Create temporary directory for certificates
        temp_dir = Path(tempfile.gettempdir()) / "bsv_test_certs"
        temp_dir.mkdir(exist_ok=True)
        
        cert_file = temp_dir / "test_cert.pem"
        key_file = temp_dir / "test_key.pem"
        
        # Check if files already exist and are valid
        if cert_file.exists() and key_file.exists():
            try:
                # Verify they can be loaded
                # PROTOCOL_TLS_SERVER uses secure defaults in Python 3.10+
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # noqa: S502  # NOSONAR - Modern TLS protocol
                context.load_cert_chain(str(cert_file), str(key_file))
                cls._cert_cache[cache_key] = (str(cert_file), str(key_file))
                return cls._cert_cache[cache_key]
            except Exception:
                # Files are corrupted, regenerate
                pass
        
        # Generate new certificate
        cls._generate_self_signed_cert(cert_file, key_file)
        
        cls._cert_cache[cache_key] = (str(cert_file), str(key_file))
        return cls._cert_cache[cache_key]
    
    @classmethod
    def _generate_self_signed_cert(cls, cert_path, key_path):
        """
        Generate a self-signed certificate for localhost.
        
        Args:
            cert_path: Path to save the certificate
            key_path: Path to save the private key
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BSV Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            # Certificate valid for 1 year
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("*.localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Write certificate to file
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Write private key to file
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))


# Convenience functions
def get_server_ssl_context():
    """Get SSL context for test servers."""
    return TestSSLHelper.get_ssl_context(for_server=True)


def get_client_ssl_context():
    """Get SSL context for test clients (accepts self-signed certs)."""
    return TestSSLHelper.get_ssl_context(for_client=True)

