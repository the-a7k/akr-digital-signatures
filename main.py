from certificate_authority import CertificateAuthority
from certificate_user import CertificateUser
import datetime

# Delete after testing
from cryptography import x509
from cryptography.hazmat.primitives import hashes


if __name__ == "__main__":
    # Certificate authority information
    CA_COUNTRY = "CZ"
    CA_STATE_OR_PROVINCE = "Jihomoravský kraj"
    CA_LOCALITY = "Brno"
    CA_ORGANIZATION = "IBE06"
    CA_COMMON_NAME = "www.fekt.vut.cz"
    CA_NOT_VALID_BEFORE = datetime.datetime(2025, 3, 26, 14, 0, 0, tzinfo=datetime.timezone.utc)
    CA_NOT_VALID_AFTER = datetime.datetime(2026, 3, 26, 14, 0, 0, tzinfo=datetime.timezone.utc)

    # CA certificate/private key file information
    CA_FILE_SAVE_PATH = "out\\CertificateAuthority\\"
    CA_CERT_FILE_NAME = "ca_certificate"
    CA_KEY_FILE_NAME = "ca_private_key"
    CA_KEY_FILE_PASSWORD = "nevimheslo123"

    # Generated CA object
    ca = CertificateAuthority()
    ca.generate_keys_rsa()
    ca.generate_certificate_authority(
        CA_COUNTRY,
        CA_STATE_OR_PROVINCE,
        CA_LOCALITY,
        CA_ORGANIZATION,
        CA_COMMON_NAME,
        CA_NOT_VALID_BEFORE,
        CA_NOT_VALID_AFTER
    )
    ca.file_save_private_key(CA_FILE_SAVE_PATH, CA_KEY_FILE_NAME, CA_KEY_FILE_PASSWORD)
    ca.file_save_certificate(CA_FILE_SAVE_PATH, CA_CERT_FILE_NAME)


    # User certificate information
    USER_COUNTRY = "CZ"
    USER_STATE_OR_PROVINCE = "Moravskoslezský kraj"
    USER_LOCALITY = "Ostrava"
    USER_ORGANIZATION = "ChciTvujCertifikatAgentura"
    USER_COMMON_NAME = "www.chcicert.cz"
    USER_NOT_VALID_BEFORE = datetime.datetime(2025, 3, 26, 14, 0, 0, tzinfo=datetime.timezone.utc)
    USER_NOT_VALID_AFTER = datetime.datetime(2025, 5, 26, 14, 0, 0, tzinfo=datetime.timezone.utc)

    # User certificate file information
    USER_FILE_SAVE_PATH = "out\\Certificates\\"
    USER_CERT_FILE_NAME = "VygenerovanyCertifikatProUsera"

    # User certificate object
    user = CertificateUser()
    user.generate_keys_rsa()

    # Creating a CSR for CA to sign
    user.certificate_signing_request(
            USER_COUNTRY,
            USER_STATE_OR_PROVINCE,
            USER_LOCALITY,
            USER_ORGANIZATION,
            USER_COMMON_NAME 
    )
    # CA issuing certificate on user's request
    ca.issue_certificate(
        user,
        USER_NOT_VALID_BEFORE, 
        USER_NOT_VALID_AFTER, 
        USER_FILE_SAVE_PATH, 
        USER_CERT_FILE_NAME
    )

    print(ca)
    print("\n")
    print(user)
    print("\nJe vygenerovany certifikat validni?", ca.verify_certificate(user.certificate))

    # Certificate verification test
    print("Je prosly certifikat validni?", ca.verify_certificate(
        x509.CertificateBuilder()
            .subject_name(user.certificate.subject)
            .issuer_name(ca.certificate.issuer) 
            .public_key(ca.public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2025, 1, 26, 14, 0, 0, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2025, 3, 26, 14, 0, 0, tzinfo=datetime.timezone.utc))  # Not valid after 26.03.
            .add_extension(x509.BasicConstraints(
                ca=False, path_length=None),
                critical=True
            )
            .sign(ca.private_key, hashes.SHA256())
        )
    )

    print("Je certifikat s issuerem, ktery neni CA, validni?", ca.verify_certificate(
        x509.CertificateBuilder()
            .subject_name(user.certificate.subject)
            .issuer_name(user.certificate.issuer)  # Issuer should be CA 
            .public_key(ca.public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2025, 1, 26, 14, 0, 0, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2025, 3, 26, 14, 0, 0, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(
                ca=False, path_length=None),
                critical=True
            )
            .sign(ca.private_key, hashes.SHA256())
        )
    )

    print("Je certifikat pred platnosti validni?", ca.verify_certificate(
        x509.CertificateBuilder()
            .subject_name(user.certificate.subject)
            .issuer_name(user.certificate.issuer) 
            .public_key(ca.public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2025, 7, 26, 14, 0, 0, tzinfo=datetime.timezone.utc))  # Valid on 26.07.
            .not_valid_after(datetime.datetime(2025, 8, 26, 14, 0, 0, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(
                ca=False, path_length=None),
                critical=True
            )
            .sign(ca.private_key, hashes.SHA256())
        )
    )

    print("Je certifikat nepodepsany private klicem od CA validni?", ca.verify_certificate(
        x509.CertificateBuilder()
            .subject_name(user.certificate.subject)
            .issuer_name(ca.certificate.issuer)
            .public_key(ca.public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2025, 1, 26, 14, 0, 0, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2025, 3, 26, 14, 0, 0, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(
                ca=False, path_length=None),
                critical=True
            )
            .sign(user.private_key, hashes.SHA256())  # Should be signed by CA
        )
    )

    print("Je validni certifikat... validni?", ca.verify_certificate(
        x509.CertificateBuilder()
            .subject_name(user.certificate.subject)
            .issuer_name(ca.certificate.issuer)
            .public_key(ca.public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2025, 1, 26, 14, 0, 0, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2025, 9, 26, 14, 0, 0, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(
                ca=False, path_length=None),
                critical=True
            )
            .sign(ca.private_key, hashes.SHA256())
        )
    )

    """
    # CA object loaded from file
    loaded_ca = CertificateAuthority()
    loaded_ca.file_load_private_key(CA_FILE_SAVE_PATH, CA_KEY_FILE_NAME, CA_KEY_FILE_PASSWORD)
    loaded_ca.file_load_certificate(CA_FILE_SAVE_PATH, CA_CERT_FILE_NAME)

    print("Shoduji se vygenerovany a nacteny privatni klic?", ca.private_key.private_numbers() == loaded_ca.private_key.private_numbers())
    print("Shoduji se vygenerovany a nacteny verejny klic?", ca.public_key.public_numbers() == loaded_ca.public_key.public_numbers())
    print("Shoduji se vygenerovany a nacteny certifikat?", ca == loaded_ca)
    print(loaded_ca)
    """
    input("...")
