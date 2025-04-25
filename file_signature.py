import hashlib

class FileSignature:
    def __init__(self, rsa_key_object, file_path):
        # Extract RSA key parameters
        numbers = rsa_key_object.private_numbers()
        self.modulus = numbers.public_numbers.n
        self.public_exponent = numbers.public_numbers.e
        self.private_exponent = numbers.d
        self.file_path = file_path 
        self.signature = pow(
            FileSignature.to_SHA256(file_path), 
            self.private_exponent, 
            self.modulus
        ) # Hash ^ PrivateExponent mod Modulus = RSA Signature

    @staticmethod
    def to_SHA256(path):
        with open(path, "rb") as f:
            data = f.read()
            digest = hashlib.sha256(data).digest()
            return int.from_bytes(digest, byteorder="big")

    def verify_signature_rsa(self, hash_to_verify_int):
        # RSA Signature ^ PublicExponent mod Modulus = Hash (to compare with)
        verified_hash = pow(self.signature, self.public_exponent, self.modulus)
        return verified_hash == hash_to_verify_int

    def create_signed_file(self, output_path):
        pass

    @staticmethod
    def read_signed_file(path):
        pass



