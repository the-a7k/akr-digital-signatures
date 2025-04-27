from os import path

# Certificate authority information
CA_COUNTRY = "CZ"
CA_STATE_OR_PROVINCE = "Jihomoravský kraj"
CA_LOCALITY = "Brno"
CA_ORGANIZATION = "IBE06"
CA_COMMON_NAME = "www.fekt.vut.cz"

# How many days is the certificate valid 
CA_VALIDITY_DAYS = 3650
USER_VALIDITY_DAYS = 365

# CA certificate/private key file information
CA_FILE_SAVE_PATH = path.join("resources", "CertificateAuthority")
CA_CERT_FILE_NAME = "ca_certificate"
CA_KEY_FILE_NAME = "ca_private_key"
CA_KEY_FILE_PASSWORD = "nevimheslo123"

# Normalized file temp directory
FILE_TEMP_DIRECTORY = path.join("resources", "Temp")
USER_FILE_SAVE_PATH = path.join("resources", "Users")

# User certificate default information
USER_COUNTRY = "CZ"
USER_STATE_OR_PROVINCE = "Neuvedeno"
USER_LOCALITY = "Neuvedeno"
USER_ORGANIZATION = "Neuvedeno"
USER_COMMON_NAME = "www.vut.cz"
USER_CERT_SUFFIX = "_certificate"
USER_KEY_SUFFIX = "_private_key"

# File general signature information
FILE_OUTPUT_NAME_SUFFIX = "_signed"
FILE_UNKNOWN_SIGNAGE_FILETYPE_SUFFIX = ".sig"
