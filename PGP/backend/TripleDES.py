from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class TripleDES:
    @staticmethod
    def encrypt(plaintext_string, key_string) -> tuple[bytes, bytes]:
        key_bytes = key_string.encode("utf-8")
        initialization_vector_bytes = get_random_bytes(DES3.block_size)
        des3 = DES3.new(key_bytes, DES3.MODE_CBC, initialization_vector_bytes)
        plaintext_bytes = plaintext_string.encode("utf-8")
        ciphertext_bytes = des3.encrypt(pad(plaintext_bytes, DES3.block_size))
        return initialization_vector_bytes, ciphertext_bytes

    @staticmethod
    def decrypt(ciphertext_bytes, initialization_vector_bytes, key_bytes) -> str:
        des3 = DES3.new(key_bytes, DES3.MODE_CBC, initialization_vector_bytes)
        plaintext_bytes = unpad(des3.decrypt(ciphertext_bytes), DES3.block_size)
        plaintext_string = plaintext_bytes.decode("utf-8")
        return plaintext_string
