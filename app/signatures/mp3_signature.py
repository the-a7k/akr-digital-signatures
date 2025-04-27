from .file_signature import FileSignature
from mutagen.id3 import ID3, TXXX, ID3NoHeaderError
from mutagen.mp3 import MP3
from shutil import copy2
from time import time
import os


class MP3Signature(FileSignature):
    def __init__(self, rsa_key_object, file_path):
        super().__init__(rsa_key_object, file_path)
        self.METADATA_NAME = "Signature"
        self.MP3_EXTENSION = ".mp3"
        self.USER_DEFINED_DATA = "TXXX"

    def copy_mp3(self, src, dest):
        try:
            copy2(src, dest)
            return True
        except Exception as e:
            return False

    def normalize_mp3(self, temp_directory):
        # Create a copy of the MP3 file
        FileSignature.directory_create(temp_directory)
        normalized_mp3_path = os.path.join(temp_directory, str(int(time())) + self.MP3_EXTENSION)
        self.copy_mp3(self.file_path, normalized_mp3_path)
        self.file_path = normalized_mp3_path
        self.hash = self.calculate_hash()
        self.signature = self.calculate_signature()
        return True

    def create_signature_mp3(self, path):
        # Add a signature to a MP3 file metadata (tags)
        try:
            tags = ID3(self.file_path)
        except ID3NoHeaderError:
            tags = ID3()  # Create ID3 header if does not exits
        try:
            # Add the signature (in base64 format) to the ID3 tags
            tags.add(TXXX(encoding=3, desc=self.METADATA_NAME, text=FileSignature.int_to_base64(self.signature)))  
            tags.save(self.file_path) # Save the tags to the MP3 file
            self.copy_mp3(self.file_path, path)
            return True
        except Exception as e:
            return False
        
    def read_signature_mp3(self, path):
        # Read the signature from the MP3 file metadata (tags)
        try:
            tags = ID3(path)
            # Go through all TXXX frames and find the one with signature
            for frame in tags.getall(self.USER_DEFINED_DATA):
                if frame.desc == self.METADATA_NAME:
                    return FileSignature.base64_to_int(frame.text[0])
            return None
        except Exception as e:
            return None

    def remove_signature_mp3(self, input_mp3_path, output_mp3_path):
        # Remove the signature from the MP3 file metadata (tags)
        try:
            self.copy_mp3(input_mp3_path, output_mp3_path)
            tags = ID3(output_mp3_path)
            frames_to_remove = []

            # Check for all signature frames, add them to a list
            for frame in tags.getall(self.USER_DEFINED_DATA):
                if frame.desc == self.METADATA_NAME:
                    frames_to_remove.append(frame.HashKey)

            # Remove the frames from the tags
            for key in frames_to_remove:
                if key in tags:
                    del tags[key]

            # Save changes to the MP3 file
            tags.save(output_mp3_path)
            return True
        except Exception as e:
            return False