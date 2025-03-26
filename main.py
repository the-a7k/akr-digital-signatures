from certificate_authority import CertificateAuthority
import datetime

if (__name__ == "__main__"):

    # Certificate authority information
    CA_COUNTRY = "CZ"
    CA_STATE_OR_PROVINCE = "Jihomoravský"
    CA_LOCALITY = "Brno"
    CA_ORGANIZATION = "BPC-IBE"
    CA_COMMON_NAME = "SK06"

    CA_NOT_VALID_BEFORE = datetime.datetime(2025, 3, 26, 14, 0, 0, tzinfo=datetime.timezone.utc)
    CA_NOT_VALID_AFTER = datetime.datetime(2026, 3, 26, 14, 0, 0, tzinfo=datetime.timezone.utc)

    CA_FILE_SAVE_PATH = "CA\\"
    CA_FILE_KEY_PASSWORD = "nevimheslo123"

    # RSA parameters
    RSA_PUBLIC_EXPONENT = 65537
    RSA_KEY_SIZE = 2048


    # Generated CA object
    created_ca = CertificateAuthority()
    created_ca.generate_keys(RSA_PUBLIC_EXPONENT, RSA_KEY_SIZE)
    created_ca.generate_certificate(
        CA_COUNTRY,
        CA_STATE_OR_PROVINCE,
        CA_LOCALITY,
        CA_ORGANIZATION,
        CA_COMMON_NAME,
        CA_NOT_VALID_BEFORE,
        CA_NOT_VALID_AFTER
    )
    created_ca.file_save_private_key(CA_FILE_SAVE_PATH, CA_FILE_KEY_PASSWORD)
    created_ca.file_save_certificate(CA_FILE_SAVE_PATH)

    # CA object loaded from file
    loaded_ca = CertificateAuthority()
    loaded_ca.file_load_private_key(CA_FILE_SAVE_PATH, CA_FILE_KEY_PASSWORD)
    loaded_ca.file_load_certificate(CA_FILE_SAVE_PATH)


    print("Shoduji se vygenerovany a nacteny privatni klic?", created_ca.private_key.private_numbers() == loaded_ca.private_key.private_numbers())
    print("Shoduji se vygenerovany a nacteny verejny klic?", created_ca.public_key.public_numbers() == loaded_ca.public_key.public_numbers())
    print("Shoduji se vygenerovany a nacteny certifikat?", created_ca == loaded_ca)

    print(created_ca)
    print(loaded_ca)
    input("...")
