from os import path
from datetime import datetime, timedelta

# Certificate authority information
CA_COUNTRY = "CZ"
CA_STATE_OR_PROVINCE = "Jihomoravsky kraj"
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
CA_NOT_VALID_BEFORE = datetime.now().astimezone()
CA_NOT_VALID_AFTER = datetime.now().astimezone() + timedelta(days=CA_VALIDITY_DAYS)

# User certificate default information
USER_COUNTRY = "CZ"
USER_STATE_OR_PROVINCE = "Not Specified"
USER_LOCALITY = "Not Specified"
USER_CERT_SUFFIX = "_certificate"
USER_KEY_SUFFIX = "_private_key"
USER_NOT_VALID_BEFORE = datetime.now().astimezone()
USER_NOT_VALID_AFTER = datetime.now().astimezone() + timedelta(days=USER_VALIDITY_DAYS)

# Normalized file temp directory
FILE_TEMP_DIRECTORY = path.join("resources", "Temp")
USER_FILE_SAVE_PATH = path.join("resources", "Users")

# File general signature information
FILE_OUTPUT_NAME_SUFFIX = "_signed"
FILE_UNKNOWN_SIGNAGE_FILETYPE_EXTENSION = ".sig"
