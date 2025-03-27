from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from hashlib import sha256
import os


class CertificateIO:
    def __init__(self):
        self.private_key = None  # Contains RSA key object
        self.public_key = None   # Contains RSA key object
        self.certificate = None  # Contains x509 certificate object

    def __str__(self):
        # Get certificate instance parameters
        if self.certificate is None:
            return (
                f"{type(self).__name__}:\n"
                f"\tCertificate is not initialized!"
            )
        
        elif self.public_key is None:
            return (
                f"{type(self).__name__}:\n"
                f"\tPublic key is not initialized!"
            )
        elif self.private_key is None:
            return (
                f"{type(self).__name__}:\n"
                f"\tPrivate key is not initialized!"
            )
        
        return (
            f"{type(self).__name__}:\n"
            f"\tSubject: {self.certificate.subject}\n"
            f"\tIssuer: {self.certificate.issuer}\n"
            f"\tCountry: {self.certificate.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value}\n"
            f"\tState/Province: {self.certificate.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value}\n"
            f"\tLocality: {self.certificate.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value}\n"
            f"\tOrganization: {self.certificate.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value}\n"
            f"\tCommon Name: {self.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}\n"
            f"\tNot Valid Before: {self.certificate.not_valid_before_utc}\n"
            f"\tNot Valid After: {self.certificate.not_valid_after_utc}\n"
            f"\tPublic Key Object: {self.public_key}\n"
            f"\tPrivate Key Object: {self.private_key}"
        )
    
    def __eq__(self, other):
        # Compare hashes of two instances
        if not isinstance(other, self.__class__):
            return False
        
        return sha256(str(self.certificate).encode()).hexdigest() == sha256(str(other.certificate).encode()).hexdigest()

    def generate_keys_rsa(self, public_exponent=65537, key_size=2048):
        # Generate CA keypair and save it into an instance
        self.private_key = rsa.generate_private_key(
            public_exponent = public_exponent,
            key_size = key_size
        )
        self.public_key = self.private_key.public_key()

    def file_create_directory(self, path):
        if not os.path.exists(path):
            os.makedirs(path)
    
    def file_save_private_key(self, path, file_name, password=None, private_key=None):
        # Save private key to .pem file
        if private_key is None and self.private_key is not None:
            # If private_key is not in self.private_key, change the last parameter for any different private key to save to file
            private_key = self.private_key
        elif private_key is None and self.private_key is None:
            # Trying to save uninitialized private key value
            return False

        self.file_create_directory(path)

        KEY_EXTENSION = ".pem"
        full_path = path + file_name + KEY_EXTENSION

        with open(full_path, "wb") as key_file:
            if password is None:
                key_file.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                )
            else:
                key_file.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
                    )
                )
    
    def file_save_certificate(self, path, file_name, certificate=None):
        # Save certificate to .pem file
        if certificate is None and self.certificate is not None:
            # If certificate is not in self.certificate, change the last parameter for any different certificate to save to file
            certificate = self.certificate
        elif certificate is None and self.certificate is None:
            # Trying to save uninitialized certificate value
            return False

        self.file_create_directory(path)

        CERT_EXTENSION = ".pem"
        full_path = path + file_name + CERT_EXTENSION

        with open(full_path, "wb") as cert_file:
            cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

    def file_load_private_key(self, path, file_name, password=None):
        # Load private key from .pem file
        KEY_EXTENSION = ".pem"
        full_path = path + file_name + KEY_EXTENSION

        self.file_create_directory(path)
        with open(full_path, "rb") as key_file:
            if password is None:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password = None
                )
            else:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password = password.encode()
                )

    def file_load_certificate(self, path, file_name):
        # Load certificate and its public key from .pem file
        CERT_EXTENSION = ".pem"
        full_path = path + file_name + CERT_EXTENSION

        self.file_create_directory(path)

        with open(full_path, "rb") as cert_file:
            ca_cert = x509.load_pem_x509_certificate(cert_file.read())
            self.certificate = ca_cert
            self.public_key = ca_cert.public_key()

