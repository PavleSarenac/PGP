from rsa import *

from backend.KeyRings import KeyRings


class RSA:
    @staticmethod
    def generate_new_key_pair(
            user_name,
            user_email,
            key_size_in_bits,
            private_key_password
    ) -> tuple[PublicKey, PrivateKey]:
        public_key, private_key = newkeys(key_size_in_bits)
        KeyRings.insert_into_private_key_ring(user_name, user_email, private_key_password, public_key, private_key)
        return public_key, private_key

    @staticmethod
    def encrypt(plaintext_string, public_key) -> bytes:
        plaintext_bytes = plaintext_string.encode("utf-8")
        ciphertext_bytes = encrypt(plaintext_bytes, public_key)
        return ciphertext_bytes

    @staticmethod
    def decrypt(ciphertext_bytes, private_key) -> str:
        plaintext_bytes = decrypt(ciphertext_bytes, private_key)
        plaintext_string = plaintext_bytes.decode("utf-8")
        return plaintext_string

    @staticmethod
    def sign_message(plaintext_string, private_key) -> bytes | None:
        try:
            plaintext_bytes = plaintext_string.encode("utf-8")
            signature = sign(plaintext_bytes, private_key, "SHA-1")
            return signature
        except OverflowError as exception:
            print(f"Signing error: {exception}")
            return None

    @staticmethod
    def verify_message(plaintext_string, signature, public_key) -> bool:
        try:
            plaintext_bytes = plaintext_string.encode("utf-8")
            hash_method = verify(plaintext_bytes, signature, public_key)
            return hash_method == "SHA-1"
        except VerificationError as exception:
            print(f"Verification error: {exception}")
            return False

    @staticmethod
    def export_key_to_pem_format(key) -> bytes:
        return key.save_pkcs1(format="PEM")

    @staticmethod
    def import_public_key_from_pem_format(public_key_bytes) -> PublicKey:
        return PublicKey.load_pkcs1(keyfile=public_key_bytes, format="PEM")

    @staticmethod
    def import_private_key_from_pem_format(private_key_bytes) -> PrivateKey:
        return PrivateKey.load_pkcs1(keyfile=private_key_bytes, format="PEM")
