from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from hashlib import sha256
import os

class CertificateAuthority:
    def __init__(self):
        self.private_key = None  # Contains RSA key object
        self.public_key = None   # Contains RSA key object
        self.certificate = None  # Contains x509 certificate object

    def __str__(self):
        # Get CA instance parameters
        if self.certificate is None:
            return(f"CA certificate is not initialized!")
        
        elif self.public_key is None or self.private_key is None:
            return(f"Keypair is not initialized!")
        
        return (
            f"CA parameters:\n"
            f"\tSubject: {self.certificate.subject}\n"
            f"\tIssuer: {self.certificate.subject}\n"
            f"\tCountry: {self.certificate.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value}\n"
            f"\tState/Province: {self.certificate.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value}\n"
            f"\tLocality: {self.certificate.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value}\n"
            f"\tOrganization: {self.certificate.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value}\n"
            f"\tCommon Name: {self.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}\n"
            f"\tNot valid before: {self.certificate.not_valid_before_utc}\n"
            f"\tNot valid after: {self.certificate.not_valid_after_utc}\n"
            f"\tPublic Key: {'Set' if self.public_key else 'Not Set'}\n"
            f"\tPrivate Key: {'Set' if self.private_key else 'Not Set'}"
        )

    def __eq__(self, other):
        # Compare two hashes of two instances
        return sha256(str(self.certificate).encode()).hexdigest() == sha256(str(other.certificate).encode()).hexdigest()
    
    def generate_keys(self, public_exponent, key_size):
        # Generate CA keypair and save it into an instance
        self.private_key = rsa.generate_private_key(
            public_exponent = public_exponent,
            key_size = key_size
        )
        self.public_key = self.private_key.public_key()
    
    def generate_certificate(self, country, state_or_province, locality, organization, common_name, not_valid_before, not_valid_after):
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
                .issuer_name(issuer)  # Same as subject
                .public_key(self.public_key)
                .serial_number(x509.random_serial_number())
                .not_valid_before(not_valid_before)  # Certificate valid from
                .not_valid_after(not_valid_after)  # Certificate valid until
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None), critical=True
                )  # Mark as CA certificate
                .sign(self.private_key, hashes.SHA256())  # Self-sign the certificate
        )

        self.certificate = certificate

    def __file_create_directory(self, path):
        if not os.path.exists(path):
            os.makedirs(path)
    
    def file_save_private_key(self, path, password):
        # Save private key to .pem file
        if self.private_key is None:
            return False
        
        self.__file_create_directory(path)

        KEY_EXTENSION = ".pem"
        KEY_NAME = "ca_private_key"
        full_path = path + KEY_NAME + KEY_EXTENSION

        with open(full_path, "wb") as key_file:
            key_file.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
                )
            )
    
    def file_save_certificate(self, path):
        # Save certificate to .pem file
        if self.certificate is None:
            return False
        
        self.__file_create_directory(path)

        CERT_EXTENSION = ".pem"
        CERT_NAME = "ca_certificate"
        full_path = path + CERT_NAME + CERT_EXTENSION

        with open(full_path, "wb") as cert_file:
            cert_file.write(self.certificate.public_bytes(serialization.Encoding.PEM))

    def file_load_private_key(self, path, password):
        # Load private key from .pem file
        KEY_EXTENSION = ".pem"
        KEY_NAME = "ca_private_key"
        full_path = path + KEY_NAME + KEY_EXTENSION

        self.__file_create_directory(path)

        with open(full_path, "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password = password.encode()
            )

    def file_load_certificate(self, path):
        # Load certificate from .pem file
        CERT_EXTENSION = ".pem"
        CERT_NAME = "ca_certificate"
        full_path = path + CERT_NAME + CERT_EXTENSION

        self.__file_create_directory(path)

        with open(full_path, "rb") as cert_file:
            ca_cert = x509.load_pem_x509_certificate(cert_file.read())
            self.certificate = ca_cert
            self.public_key = ca_cert.public_key()
