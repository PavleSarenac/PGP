from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class AES128:
    @staticmethod
    def encrypt(plaintext_string, key_string) -> tuple[bytes, bytes]:
        key_bytes = key_string.encode("utf-8")
        initialization_vector_bytes = get_random_bytes(AES.block_size)
        aes128 = AES.new(key_bytes, AES.MODE_CBC, initialization_vector_bytes)
        plaintext_bytes = plaintext_string.encode("utf-8")
        ciphertext_bytes = aes128.encrypt(pad(plaintext_bytes, AES.block_size))
        return initialization_vector_bytes, ciphertext_bytes

    @staticmethod
    def decrypt(ciphertext_bytes, initialization_vector_bytes, key_bytes) -> str:
        aes128 = AES.new(key_bytes, AES.MODE_CBC, initialization_vector_bytes)
        plaintext_bytes = unpad(aes128.decrypt(ciphertext_bytes), AES.block_size)
        plaintext_string = plaintext_bytes.decode("utf-8")
        return plaintext_string
