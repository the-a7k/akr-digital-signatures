from certificate_authority import CertificateAuthority
from certificate_user import CertificateUser
import constants as const
from datetime import datetime, timedelta


if __name__ == "__main__":
    cert_auth = CertificateAuthority()

    # Load CA certificate and private key from files, if they exist
    # If they do not exist, generate them and save to files
    if (cert_auth.file_load_certificate(
            const.CA_FILE_SAVE_PATH, 
            const.CA_CERT_FILE_NAME) is False
        or cert_auth.file_load_private_key(
            const.CA_FILE_SAVE_PATH, 
            const.CA_KEY_FILE_NAME, 
            const.CA_KEY_FILE_PASSWORD) is False):
        
        # Generate CA certificate and private key
        cert_auth.generate_keys_rsa()
        cert_auth.generate_certificate_authority(
            const.CA_COUNTRY,
            const.CA_STATE_OR_PROVINCE,
            const.CA_LOCALITY,
            const.CA_ORGANIZATION,
            const.CA_COMMON_NAME,
            not_valid_before=datetime.now().astimezone(),
            not_valid_after=datetime.now().astimezone() + timedelta(days=const.CA_VALIDITY_DAYS)
        )
        # Save CA certificate and private key to files
        cert_auth.file_save_private_key(const.CA_FILE_SAVE_PATH, const.CA_KEY_FILE_NAME, const.CA_KEY_FILE_PASSWORD)
        cert_auth.file_save_certificate(const.CA_FILE_SAVE_PATH, const.CA_CERT_FILE_NAME)

    print(cert_auth)
    print(cert_auth.get_certificate_not_valid_after())
    print(cert_auth.get_certificate_not_valid_before())
