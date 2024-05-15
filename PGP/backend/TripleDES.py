from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class TripleDES:
    @staticmethod
    def encrypt(plaintext, key) -> tuple[bytes, bytes]:
        plaintext_bytes = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
        key_bytes = key.encode("utf-8") if isinstance(key, str) else key
        initialization_vector_bytes = get_random_bytes(DES3.block_size)
        des3 = DES3.new(key_bytes, DES3.MODE_CBC, initialization_vector_bytes)
        ciphertext_bytes = des3.encrypt(pad(plaintext_bytes, DES3.block_size))
        return initialization_vector_bytes, ciphertext_bytes

    @staticmethod
    def decrypt(ciphertext, initialization_vector, key) -> str:
        ciphertext_bytes = ciphertext.encode("utf-8") if isinstance(ciphertext, str) else ciphertext
        initialization_vector_bytes = ciphertext.encode("utf-8") if isinstance(initialization_vector, str) else initialization_vector
        key_bytes = key.encode("utf-8") if isinstance(key, str) else key
        des3 = DES3.new(key_bytes, DES3.MODE_CBC, initialization_vector_bytes)
        plaintext_bytes = unpad(des3.decrypt(ciphertext_bytes), DES3.block_size)
        plaintext_string = plaintext_bytes.decode("utf-8")
        return plaintext_string
