from PyPDF2 import PdfReader, PdfWriter
from file_signature import FileSignature
from time import time
import os
import shutil

class PDFSignature(FileSignature):
    def __init__(self, rsa_key_object, file_path):
        super().__init__(rsa_key_object, file_path)

    def file_create_directory(self, path):
        if not os.path.exists(path):
            os.makedirs(path)

    @staticmethod
    def file_remove_directory(path):
        # Remove the directory and all its contents
        try:
            shutil.rmtree(path)
            return True
        except Exception as e:
            return False

    def normalize_pdf(self, temp_directory):
        # Create a new PDF file with the same content as the original one
        PDF_EXTENSION = ".pdf"

        with open(self.file_path, "rb") as input_pdf_file:
            pdf_reader = PdfReader(input_pdf_file)
            pdf_writer = PdfWriter()

            # Copy pages from the original PDF to the new PDF
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                pdf_writer.add_page(page)

            self.file_create_directory(temp_directory)

            # Save the normalized PDF to a temporary directory with a unique name (according to UNIX timestamp)
            normalized_pdf_path = os.path.join(temp_directory, str(int(time())) + PDF_EXTENSION)
            with open(normalized_pdf_path, "wb") as normalized_pdf_file:
                pdf_writer.write(normalized_pdf_file)
        
        # Uodate the file path, hash and signature of the PDF object
        self.file_path = normalized_pdf_path
        self.hash = self.calculate_SHA256()
        self.signature = self.calculate_signature()

    def create_signature_pdf(self, path):
        with open(self.file_path, "rb") as input_pdf_file:
            pdf_reader = PdfReader(input_pdf_file)
            pdf_writer = PdfWriter()
            
            # Copy pages from the original PDF to the new PDF
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                pdf_writer.add_page(page)
            
            # Update and add new metadata as string to the PDF
            metadata = pdf_reader.metadata
            metadata.update({
                "/Signature": FileSignature.int_to_base64(self.signature)
            })
            pdf_writer.add_metadata(metadata)
            
            # Create a new PDF with the updated metadata
            with open(path, "wb") as output_pdf_file:
                pdf_writer.write(output_pdf_file)


    def read_signature_pdf(self, path):
        if not os.path.isfile(path):
            # File does not exist
            return False

        with open(path, "rb") as file:
            pdf_reader = PdfReader(file)
            # Read the metadata from the PDF
            metadata = pdf_reader.metadata
            signature = metadata.get("/Signature", None)
            
            if signature:
                return FileSignature.base64_to_int(signature)
            
            return False
    
    def remove_signature_pdf(self, output_pdf_path):
        with open(self.file_path, "rb") as input_pdf_file:
            pdf_reader = PdfReader(input_pdf_file)
            pdf_writer = PdfWriter()
            
            # Copy pages from the original PDF to the new PDF
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                pdf_writer.add_page(page)
            
            # Load metadata
            metadata = pdf_reader.metadata
            
            # Remove the signature metadata (if it exists)
            if "/Signature" in metadata:
                del metadata["/Signature"]
            pdf_writer.add_metadata(metadata)
            
            # Save the new PDF without the signature
            with open(output_pdf_path, "wb") as output_pdf_file:
                pdf_writer.write(output_pdf_file)
