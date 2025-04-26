import hashlib
from base64 import b64encode, b64decode
import os

class FileSignature:
    def __init__(self, rsa_key_object, file_path):
        # Extract RSA key parameters
        numbers = rsa_key_object.private_numbers()
        self.modulus = numbers.public_numbers.n
        self.public_exponent = numbers.public_numbers.e
        self.private_exponent = numbers.d
        self.file_path = file_path
        self.hash = self.calculate_SHA256()             # In integer format
        self.signature = self.calculate_signature()     # In integer format

    def calculate_SHA256(self):
        # Get the SHA256 hash of the file
        with open(self.file_path, "rb") as f:
            data = f.read()
            digest = hashlib.sha256(data).digest()
            return int.from_bytes(digest, byteorder="big")

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
        with open(path, "w") as f:
            f.write(FileSignature.int_to_base64(self.signature))

    def read_signature_file(self, path):
        if not os.path.isfile(path):
            # File does not exist
            return False

        with open(path, "r") as f:
            return FileSignature.base64_to_int(f.read())
        
    @staticmethod
    def int_to_base64(number):
        bytes = number.to_bytes((number.bit_length() + 7) // 8, byteorder="big")
        return b64encode(bytes).decode('utf-8')
    
    @staticmethod
    def base64_to_int(b64_string):
        byte_array = b64decode(b64_string)
        return int.from_bytes(byte_array, byteorder="big")



