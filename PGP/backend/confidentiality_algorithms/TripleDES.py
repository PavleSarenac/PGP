from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class TripleDES:
    @staticmethod
    def encrypt(plaintext, key) -> tuple[bytes, bytes]:
        plaintext_bytes = plaintext.encode("utf-8") if not isinstance(plaintext, bytes) else plaintext
        key_bytes = key.encode("utf-8") if not isinstance(key, bytes) else key
        initialization_vector_bytes = get_random_bytes(DES3.block_size)
        des3 = DES3.new(key_bytes, DES3.MODE_CFB, initialization_vector_bytes)
        ciphertext_bytes = des3.encrypt(pad(plaintext_bytes, DES3.block_size))
        return initialization_vector_bytes, ciphertext_bytes

    @staticmethod
    def decrypt(ciphertext, initialization_vector, key) -> bytes:
        ciphertext_bytes = ciphertext.encode("utf-8") if not isinstance(ciphertext, bytes) else ciphertext
        initialization_vector_bytes = initialization_vector.encode("utf-8") if not isinstance(initialization_vector, bytes) else initialization_vector
        key_bytes = key.encode("utf-8") if not isinstance(key, bytes) else key
        des3 = DES3.new(key_bytes, DES3.MODE_CFB, initialization_vector_bytes)
        plaintext_bytes = unpad(des3.decrypt(ciphertext_bytes), DES3.block_size)
        return plaintext_bytes
