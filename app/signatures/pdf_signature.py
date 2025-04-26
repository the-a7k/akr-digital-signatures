from .file_signature import FileSignature
from PyPDF2 import PdfReader, PdfWriter
from time import time
import os

class PDFSignature(FileSignature):
    def __init__(self, rsa_key_object, file_path):
        super().__init__(rsa_key_object, file_path)
        self.METADATA_NAME = "/Signature"
        self.PDF_EXTENSION = ".pdf"

    def normalize_pdf(self, temp_directory):
        # Create a new PDF file with the same content as the original one
        with open(self.file_path, "rb") as input_pdf_file:
            pdf_reader = PdfReader(input_pdf_file)
            pdf_writer = PdfWriter()

            # Copy pages from the original PDF to the new PDF
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                pdf_writer.add_page(page)

            FileSignature.directory_create(temp_directory)

            # Save the normalized PDF to a temporary directory with a unique name (according to UNIX timestamp)
            normalized_pdf_path = os.path.join(temp_directory, str(int(time())) + self.PDF_EXTENSION)
            with open(normalized_pdf_path, "wb") as normalized_pdf_file:
                pdf_writer.write(normalized_pdf_file)
        
        # Uodate the file path, hash and signature of the PDF object
        self.file_path = normalized_pdf_path
        self.hash = self.calculate_hash()
        self.signature = self.calculate_signature()

    def create_signature_pdf(self, path):
        # Create a new PDF with signature in the metadata
        with open(self.file_path, "rb") as input_pdf_file:
            pdf_reader = PdfReader(input_pdf_file)
            pdf_writer = PdfWriter()
            
            # Copy pages from the original PDF to the new PDF
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                pdf_writer.add_page(page)
            
            # Update and add new metadata (in base64) as string to the PDF
            metadata = pdf_reader.metadata
            metadata.update({
                self.METADATA_NAME: FileSignature.int_to_base64(self.signature)
            })
            pdf_writer.add_metadata(metadata)
            
            # Create a new PDF with the updated metadata
            with open(path, "wb") as output_pdf_file:
                pdf_writer.write(output_pdf_file)

    def read_signature_pdf(self, path):
        # Read the signature from the PDF metadata
        if not os.path.isfile(path):
            # File does not exist
            return False

        with open(path, "rb") as file:
            pdf_reader = PdfReader(file)
            # Read the metadata from the PDF
            metadata = pdf_reader.metadata
            signature = metadata.get(self.METADATA_NAME, None)
            
            if signature:
                return FileSignature.base64_to_int(signature)
            
            return False
    
    def remove_signature_pdf(self, input_pdf_path, output_pdf_path):
        # Create a new PDF without the signature in the metadata
        with open(input_pdf_path, "rb") as input_pdf_file:
            pdf_reader = PdfReader(input_pdf_file)
            pdf_writer = PdfWriter()
            
            # Copy pages from the original PDF to the new PDF
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                pdf_writer.add_page(page)
            
            # Load metadata
            metadata = pdf_reader.metadata
            
            # Remove the signature metadata (if it exists)
            if self.METADATA_NAME in metadata:
                del metadata[self.METADATA_NAME]
            pdf_writer.add_metadata(metadata)
            
            # Save the new PDF without the signature
            with open(output_pdf_path, "wb") as output_pdf_file:
                pdf_writer.write(output_pdf_file)
