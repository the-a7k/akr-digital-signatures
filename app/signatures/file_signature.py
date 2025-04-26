import hashlib
from base64 import b64encode, b64decode
import os
import shutil


class FileSignature:
    def __init__(self, rsa_key_object, file_path):
        # Extract RSA key parameters
        numbers = rsa_key_object.private_numbers()
        self.modulus = numbers.public_numbers.n
        self.public_exponent = numbers.public_numbers.e
        self.private_exponent = numbers.d
        self.file_path = file_path
        self.hash = self.calculate_hash()               # In integer format
        self.signature = self.calculate_signature()     # In integer format

    def calculate_hash(self, algorithm="sha256", chunk_size=4096):
        # Calculate a hash of the file, chunk by chunk, return the hash as an integer
        h = hashlib.new(algorithm)
        with open(self.file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        digest_bytes = h.digest() 
        return int.from_bytes(digest_bytes, byteorder="big")

    def calculate_signature(self):
        # Hash ^ PrivateExponent mod Modulus = RSA Signature
        return pow(self.hash, self.private_exponent, self.modulus)

    def compare_signature(self, signature_to_verify_int):
        # Hash ^ PrivateExponent mod Modulus = RSA Signature
        return self.signature == signature_to_verify_int

    def compare_SHA256(self, hash_to_verify_int):
        # RSA Signature ^ PublicExponent mod Modulus = Hash
        return hash_to_verify_int == self.hash

    def create_signature_file(self, path):
        # Create a signature file with the signature in base64 format
        with open(path, "w") as f:
            f.write(FileSignature.int_to_base64(self.signature))

    def read_signature_file(self, path):
        # Read the signature from a file and convert it to an integer
        if not os.path.isfile(path):
            # File does not exist
            return False

        with open(path, "r") as f:
            return FileSignature.base64_to_int(f.read())

    @staticmethod 
    def directory_create(path):
        if not os.path.exists(path):
            os.makedirs(path)

    @staticmethod
    def directory_remove(path):
        # Remove the directory and all its contents
        try:
            shutil.rmtree(path)
            return True
        except Exception as e:
            return False
        
    @staticmethod
    def int_to_base64(number):
        # Convert an integer to a base64 string
        bytes = number.to_bytes((number.bit_length() + 7) // 8, byteorder="big")
        return b64encode(bytes).decode('utf-8')
    
    @staticmethod
    def base64_to_int(b64_string):
        # Convert a base64 string to an integer
        byte_array = b64decode(b64_string)
        return int.from_bytes(byte_array, byteorder="big")



