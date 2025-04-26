from file_signature import FileSignature
from mutagen.id3 import ID3, TXXX, ID3NoHeaderError
from mutagen.mp3 import MP3
from shutil import copy2


class MP3Signature(FileSignature):
    def __init__(self, rsa_key_object, file_path):
        super().__init__(rsa_key_object, file_path)
        self.METADATA_NAME = "Signature"
        self.MP3_EXTENSION = ".mp3"

    def create_copy_mp3(self, path):
        try:
            copy2(self.file_path, path)
            return True
        except Exception as e:
            print(f"Error copying MP3 file: {e}")
            return False

    def create_signature_mp3(self):
        # Add a signature to a MP3 file metadata
        try:
            try:
                tags = ID3(self.file_path)
            except ID3NoHeaderError:
                tags = ID3()  # Create ID3 header if does not exits

            tags.add(TXXX(encoding=3, desc=self.METADATA_NAME, text=FileSignature.int_to_base64(self.signature)))  # Add the signature to the ID3 tags
            tags.save(self.file_path) # Save the tags to the MP3 file
            return True
        except Exception as e:
            print(f"Error saving signature: {e}")
            return False
        
    def read_signature_mp3(self):
        # Read the signature from the MP3 file metadata
        try:
            tags = ID3(self.file_path)
            for frame in tags.getall("TXXX"):
                if frame.desc == self.METADATA_NAME:
                    return FileSignature.base64_to_int(frame.text[0])  # první položka seznamu textů
            return None
        except Exception as e:
            print(f"Error reading signature: {e}")
            return None

    def remove_signature_mp3(self):
        # Remove the signature from the MP3 file metadata
        try:
            tags = ID3(self.file_path)
            frames_to_remove = []

            for frame in tags.getall("TXXX"):
                if frame.desc == self.METADATA_NAME:
                    frames_to_remove.append(frame.HashKey)

            for key in frames_to_remove:
                if key in tags:
                    del tags[key]

            tags.save(self.file_path)
            return True
        except Exception as e:
            print(f"Error removing signature: {e}")
            return False