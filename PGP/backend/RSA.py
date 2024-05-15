import rsa
from rsa import PublicKey, PrivateKey, newkeys, encrypt, decrypt, sign, verify


class RSA:
    @staticmethod
    def generate_new_key_pair(
            user_name,
            user_email,
            key_size_in_bits,
            private_key_password
    ) -> tuple[PublicKey, PrivateKey]:
        return newkeys(key_size_in_bits)

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
    def sign_message(plaintext_string, private_key) -> bytes:
        return sign(plaintext_string.encode("utf-8"), private_key, "SHA-1")

    @staticmethod
    def verify_message(plaintext_string, signature, public_key) -> str:
        return verify(plaintext_string.encode("utf-8"), signature, public_key)

    @staticmethod
    def export_key_to_pem_format(key) -> bytes:
        return key.save_pkcs1(format="PEM")

    @staticmethod
    def import_private_key_from_pem_format(private_key_bytes) -> PrivateKey:
        return PrivateKey.load_pkcs1(keyfile=private_key_bytes, format="PEM")

    @staticmethod
    def import_public_key_from_pem_format(public_key_bytes) -> PublicKey:
        return PublicKey.load_pkcs1(keyfile=public_key_bytes, format="PEM")


if __name__ == "__main__":
    public_key, private_key = RSA.generate_new_key_pair(
        "Pavle",
        "sarenac.pavle@gmail.com",
        1024,
        "ducakuca"
    )

    public_key_pem_format = RSA.export_key_to_pem_format(public_key)
    private_key_pem_format = RSA.export_key_to_pem_format(private_key)

    print(public_key_pem_format.decode("utf-8"))
    print(private_key_pem_format.decode("utf-8"))

    print(RSA.import_public_key_from_pem_format(public_key_pem_format))
    print(RSA.import_private_key_from_pem_format(private_key_pem_format))

    plaintext_string = "Hello world!"

    ciphertext_bytes = RSA.encrypt(plaintext_string, public_key)
    print("Ciphertext:", ciphertext_bytes)

    decrypted_text = RSA.decrypt(ciphertext_bytes, private_key)
    print("Decrypted text:", decrypted_text)

    signature = RSA.sign_message(plaintext_string, private_key)
    verification = ""
    try:
        verification = RSA.verify_message(plaintext_string, signature, public_key)
    except rsa.VerificationError:
        verification += "VERIFICATION ERROR!"

    print(signature)
    print(verification)
