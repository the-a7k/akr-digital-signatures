from .file_signature import FileSignature
from PIL import Image, PngImagePlugin
import os
from time import time


class PNGSignature(FileSignature):
    def __init__(self, rsa_key_object, file_path):
        super().__init__(rsa_key_object, file_path)
        self.METADATA_NAME = "Signature"
        self.PIL_EXTENSION = "PNG"
        self.PNG_EXTENSION = ".png"

    def normalize_png(self, temp_directory):
        # Create a normalized copy of the PNG file
        FileSignature.directory_create(temp_directory)

        # Save the normalized PNG to a temporary directory with a unique name (according to UNIX timestamp)
        normalized_png_path = os.path.join(temp_directory, str(int(time())) + self.PNG_EXTENSION)

        with Image.open(self.file_path) as img:
            img_without_meta = Image.new(img.mode, img.size)
            img_without_meta.putdata(list(img.getdata()))
            img_without_meta.save(normalized_png_path, format=self.PIL_EXTENSION)
        
        self.file_path = normalized_png_path
        self.hash = self.calculate_hash()
        self.signature = self.calculate_signature()

    def create_signature_png(self, path):
        # Create a new PNG with signature in the metadata
        try:
            img = Image.open(self.file_path)
            meta = PngImagePlugin.PngInfo()
            # Insert the signature into the metadata (in base64)
            meta.add_text(self.METADATA_NAME, FileSignature.int_to_base64(self.signature))
            img.save(path, self.PIL_EXTENSION, pnginfo=meta)
        except Exception as e:
            return False

    def read_signature_png(self, path):
        # Read the signature from the PNG metadata
        img = Image.open(path)
        value = img.info.get(self.METADATA_NAME)
        if value:
            return FileSignature.base64_to_int(value)
        return None

    def remove_signature_png(self, input_path, output_path):
        # Create a new PNG without the signature in the metadata
        try:
            img = Image.open(input_path)
            info = img.info
            new_info = PngImagePlugin.PngInfo()

            for key, value in info.items():
                # Browse the metadata, if the key is not the signature, add it to the new PNG metadata
                if key == self.METADATA_NAME:
                    continue
                new_info.add_text(key, value)

            img.save(output_path, self.PIL_EXTENSION, pnginfo=new_info)

        except Exception as e:
            return False