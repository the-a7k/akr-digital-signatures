from os import path

# Certificate authority information
CA_COUNTRY = "CZ"
CA_STATE_OR_PROVINCE = "Jihomoravský kraj"
CA_LOCALITY = "Brno"
CA_ORGANIZATION = "IBE06"
CA_COMMON_NAME = "www.fekt.vut.cz"

# How many days is the CA certificate valid 
CA_VALIDITY_DAYS = 365

# CA certificate/private key file information
CA_FILE_SAVE_PATH = path.join("resources", "CertificateAuthority")
CA_CERT_FILE_NAME = "ca_certificate"
CA_KEY_FILE_NAME = "ca_private_key"
CA_KEY_FILE_PASSWORD = "nevimheslo123"

# Normalized file temp directory
FILE_TEMP_DIRECTORY = path.join("resources", "Temp")