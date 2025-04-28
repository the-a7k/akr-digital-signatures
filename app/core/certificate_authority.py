from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime
from .certificate_io import CertificateIO


class CertificateAuthority(CertificateIO):
    def __init__(self):
        super().__init__();  # Contains private_key, public_key and certificate properties

    def __str__(self):
        return super().__str__()

    def __eq__(self, other):
        return super().__eq__(other)

    def generate_certificate_authority(self, country, state_or_province, locality, organization, common_name, not_valid_before, not_valid_after):
        # Generate CA certificate and save it into an instance
        if self.private_key is None or self.public_key is None:
            return False
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])  # Subject is the same as issuer

        certificate = (
            x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)                      # Same as subject
                .public_key(self.public_key)
                .serial_number(x509.random_serial_number())
                .not_valid_before(not_valid_before)       # Certificate valid from
                .not_valid_after(not_valid_after)         # Certificate valid until
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None), 
                    critical=True
                )                                         # Mark as CA certificate
                .sign(self.private_key, hashes.SHA256())  # Self-sign the certificate
        )

        self.certificate = certificate
        return True

    def issue_certificate(self, user_cert_instance, not_valid_before, not_valid_after, path, file_name):
        # Issue a certificate for user on Certificate Signing Request (CSR) from user and save the certificate
        if user_cert_instance.csr is None:
            return False
        
        # Generate certificate issued by CA
        user_cert = (
            x509.CertificateBuilder()
                .subject_name(user_cert_instance.csr.subject)
                .issuer_name(self.certificate.subject)           # Issuer is CA
                .public_key(user_cert_instance.public_key)       # Public key of the user
                .serial_number(x509.random_serial_number())
                .not_valid_before(not_valid_before)
                .not_valid_after(not_valid_after)
                .add_extension(x509.BasicConstraints(
                    ca=False, path_length=None), 
                    critical=True
                )                                                # Mark as non-CA certificate
                .sign(self.private_key, hashes.SHA256())         # Signing with private key of CA
        )

        # Save user certificate into directory
        self.file_save_certificate(path, file_name, user_cert)
        user_cert_instance.csr = None  # Flushing current attempt to create user certificate
        user_cert_instance.certificate = user_cert

        return True
    
    def get_certificate_not_valid_before(self):
        return self.certificate.not_valid_before_utc.astimezone() if self.certificate is not None else None
    
    def get_certificate_not_valid_after(self):
        return self.certificate.not_valid_after_utc.astimezone() if self.certificate is not None else None

    def verify_certificate(self, certificate_to_verify):
        # Check if certificate is not expired, issued by CA and signed by CA private key
        if self.certificate is None or self.private_key is None or self.public_key is None or certificate_to_verify is None:
            return False
        
        if not certificate_to_verify.not_valid_before_utc <= datetime.now().astimezone() <= certificate_to_verify.not_valid_after_utc:
            # Certificate is expired or before validity
            return False

        if certificate_to_verify.issuer != self.certificate.subject:
            # Certificate issuer is not CA
            return False
        
        # Verify signage
        try:
            self.public_key.verify(
                certificate_to_verify.signature,                # Certificate CA signing
                certificate_to_verify.tbs_certificate_bytes,    # Signed data without the signage itself
                padding.PKCS1v15(),                             # RSA padding
                certificate_to_verify.signature_hash_algorithm  # Used hashing algorithm
            )
        
        except Exception as e:
            return False
        
        return True