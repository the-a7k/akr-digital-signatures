from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from certificate_io import CertificateIO


class CertificateUser(CertificateIO):
    def __init__(self):
        super().__init__();  # Contains private_key, public_key and certificate properties
        self.csr = None      # Certificate signing request, used for CA to sign and generate user certificate

    def __str__(self):
        return super().__str__() + f"\n\tCertificate Signing Request (CSR): {self.csr}"
    
    def __eq__(self, other):
        return super().__eq__(other)

    def certificate_signing_request(self, country, state_or_province, locality, organization, common_name):
        # Generate a request for CA to issue a certificate and save it into an instance
        if self.private_key is None or self.public_key is None:
            return False

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        # Certificate signing request for CA
        csr = (
            x509.CertificateSigningRequestBuilder()
                .subject_name(subject)
                .sign(self.private_key, hashes.SHA256())  # Signing CSR with private key of a user
        )
        self.csr = csr
        
        return True

