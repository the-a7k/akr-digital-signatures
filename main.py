from certificate_authority import CertificateAuthority
from certificate_user import CertificateUser
import constants as const
from datetime import datetime, timedelta
from pdf_signature import PDFSignature
from file_signature import FileSignature
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
    * SIGNATURE TESTING
    *
    """


    user = CertificateUser()
    user.generate_keys_rsa()

    input_pdf_path = path.join("filetest", "input.pdf")                                         # Original PDF to be signed
    output_pdf_path_with_signature = path.join("filetest", "output_with_signature.pdf")         # PDF with signature in metadata
    output_pdf_path_without_signature = path.join("filetest", "output_without_signature.pdf")   # PDF to be checked against the original one

    # 1) Signature in the metadata of PDF

    og_pdf = PDFSignature(user.private_key, input_pdf_path)         # OG PDF object
    og_pdf.normalize_pdf(const.FILE_TEMP_DIRECTORY)                 # Create a normalized copy of the OG PDF
    og_pdf.create_signature_pdf(output_pdf_path_with_signature)     # Create a new PDF from the normalized one with the signature in the metadata    
    og_pdf.remove_signature_pdf(output_pdf_path_without_signature)  # Create a new PDF by removing the signature from the signed PDF

    generated_og_pdf = PDFSignature(user.private_key, output_pdf_path_without_signature)  # New PDF object from the unsigned PDF
    print("Shoduji se podpisy puvodniho a kontrolovaneho pdf?", og_pdf.compare_signature(generated_og_pdf.signature))


    # 2) Signature in separate file

    input_sig_path = path.join("filetest", "separate_signature_og.sig")
    output_sig_path = path.join("filetest", "separate_signature_generated.sig")

    og_pdf.create_signature_file(input_sig_path)
    og_sig = og_pdf.read_signature_file(input_sig_path)

    generated_og_pdf.create_signature_file(output_sig_path)
    generated_og_sig = generated_og_pdf.read_signature_file(output_sig_path)

    print("Shoduji se podpisy puvodniho pdf a kontrolovaneho sig souboru?", og_pdf.compare_signature(generated_og_sig))
    print("Shoduji se podpisy sig mezi sebou?", og_sig == generated_og_sig)


    PDFSignature.file_remove_directory(const.FILE_TEMP_DIRECTORY)  # Temp directory cleanup