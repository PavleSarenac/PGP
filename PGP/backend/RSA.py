import rsa


class RSA:
    @staticmethod
    def generate_new_key_pair(
            user_name,
            user_email,
            key_size_in_bits,
            private_key_password
    ) -> tuple[bytes, bytes]:
        (public_key, private_key) = rsa.newkeys(key_size_in_bits)
        public_key_bytes = public_key.save_pkcs1(format="PEM")
        private_key_bytes = private_key.save_pkcs1(format="PEM")
        return public_key_bytes, private_key_bytes

    @staticmethod
    def encrypt(plaintext_string, public_key_bytes) -> bytes:
        public_key = rsa.PublicKey.load_pkcs1(keyfile=public_key_bytes, format="PEM")
        plaintext_bytes = plaintext_string.encode("utf-8")
        ciphertext_bytes = rsa.encrypt(plaintext_bytes, public_key)
        return ciphertext_bytes

    @staticmethod
    def decrypt(ciphertext_bytes, private_key_bytes) -> str:
        private_key = rsa.PrivateKey.load_pkcs1(keyfile=private_key_bytes, format="PEM")
        plaintext_bytes = rsa.decrypt(ciphertext_bytes, private_key)
        plaintext_string = plaintext_bytes.decode("utf-8")
        return plaintext_string

    @staticmethod
    def sign_message(plaintext_string, private_key_bytes) -> bytes:
        private_key = rsa.PrivateKey.load_pkcs1(keyfile=private_key_bytes, format="PEM")
        return rsa.sign(plaintext_string.encode("utf-8"), private_key, "SHA-1")

    @staticmethod
    def verify_message(plaintext_string, signature, public_key_bytes) -> str:
        public_key = rsa.PublicKey.load_pkcs1(keyfile=public_key_bytes, format="PEM")
        return rsa.verify(plaintext_string.encode("utf-8"), signature, public_key)


if __name__ == "__main__":
    public_key_bytes, private_key_bytes = RSA.generate_new_key_pair(
        "Pavle",
        "sarenac.pavle@gmail.com",
        1024,
        "ducakuca"
    )

    print(public_key_bytes.decode("utf-8"))
    print(private_key_bytes.decode("utf-8"))

    plaintext_string = "Hello world!"

    ciphertext_bytes = RSA.encrypt(plaintext_string, public_key_bytes)
    print("Ciphertext:", ciphertext_bytes)

    decrypted_text = RSA.decrypt(ciphertext_bytes, private_key_bytes)
    print("Decrypted text:", decrypted_text)

    signature = RSA.sign_message(plaintext_string, private_key_bytes)
    verification = RSA.verify_message(plaintext_string, signature, public_key_bytes)
    print(signature)
    print(verification)