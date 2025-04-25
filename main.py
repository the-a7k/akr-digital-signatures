from certificate_authority import CertificateAuthority
from certificate_user import CertificateUser
import constants as const
from datetime import datetime, timedelta
from pdf_signature import PDFSignature
from os import path


if __name__ == "__main__":
    cert_auth = CertificateAuthority()

    # Load CA certificate and private key from files (if they exist)
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


    """
    * 
    * PDF SIGNATURE TESTING
    *
    """


    user = CertificateUser()
    user.generate_keys_rsa()

    input_pdf_path = path.join("filetest", "input.pdf")                                         # Original PDF to be signed
    output_pdf_path_with_signature = path.join("filetest", "output_with_signature.pdf")         # PDF with signature in metadata
    output_pdf_path_without_signature = path.join("filetest", "output_without_signature.pdf")   # PDF to be checked against the original one

    og_pdf = PDFSignature(user.private_key, input_pdf_path)     # OG PDF object
    og_pdf.normalize_pdf(const.FILE_TEMP_DIRECTORY)             # Create a normalized copy of the OG PDF
    og_pdf.create_signed_pdf(output_pdf_path_with_signature)    # Create a new PDF from the normalized one with the signature in the metadata

    signature_from_metadata = PDFSignature.read_signature(output_pdf_path_with_signature)               # Read signature from metadata
    PDFSignature.remove_signature(output_pdf_path_with_signature, output_pdf_path_without_signature)    # Remove the signature from the PDF metadata and save it to a new PDF

    new_pdf = PDFSignature(user.private_key, output_pdf_path_without_signature)                         # New PDF object (without the signature in metadata, should be the same as the normalized original)

    print(signature_from_metadata == og_pdf.signature)                                                              # Compare signature from PDF with the object (should be True)
    print(new_pdf.signature == og_pdf.signature)                                                                    # Compare new obejct and original object signatures (should be True)
    print(og_pdf.verify_signature_rsa(PDFSignature.to_SHA256(output_pdf_path_without_signature)))                   # Compare hashes (should be True)
    print(PDFSignature.to_SHA256(output_pdf_path_without_signature) == PDFSignature.to_SHA256(og_pdf.file_path))    # Compare hashes (should be True)
    
    #PDFSignature.file_remove_directory(const.FILE_TEMP_DIRECTORY)

