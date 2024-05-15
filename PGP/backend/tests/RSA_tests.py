from backend.RSA import RSA
from rsa import PublicKey, PrivateKey


def new_key_pair_generation() -> tuple[PublicKey, PrivateKey]:
    print("###########################################################################################################")
    print("NEW KEY PAIR GENERATION")
    print("###########################################################################################################")
    public_key, private_key = RSA.generate_new_key_pair(
        "Ljubica",
        "ljubmajstorovic9@gmail.com",
        1024,
        "bicabica"
    )
    print(public_key)
    print(private_key)
    print("###########################################################################################################")
    print()
    return public_key, private_key


def key_pair_export_to_pem_format(public_key, private_key) -> tuple[bytes, bytes]:
    print("###########################################################################################################")
    print("KEY PAIR EXPORT TO PEM FORMAT")
    print("###########################################################################################################")
    public_key_pem_format = RSA.export_key_to_pem_format(public_key)
    private_key_pem_format = RSA.export_key_to_pem_format(private_key)
    print(public_key_pem_format.decode("utf-8"))
    print(private_key_pem_format.decode("utf-8"))
    print("###########################################################################################################")
    print()
    return public_key_pem_format, private_key_pem_format


def key_pair_import_from_pem_format(public_key_pem_format, private_key_pem_format) -> tuple[PublicKey, PrivateKey]:
    print("###########################################################################################################")
    print("KEY PAIR IMPORT FROM PEM FORMAT")
    print("###########################################################################################################")
    public_key = RSA.import_public_key_from_pem_format(public_key_pem_format)
    private_key = RSA.import_private_key_from_pem_format(private_key_pem_format)
    print(public_key)
    print(private_key)
    print("###########################################################################################################")
    print()
    return public_key, private_key


def rsa_encryption(public_key) -> tuple[str, bytes]:
    plaintext_string = "Hello world!"
    ciphertext_bytes = RSA.encrypt(plaintext_string, public_key)
    print("###########################################################################################################")
    print("RSA ENCRYPTION")
    print("###########################################################################################################")
    print(f"Plaintext string: {plaintext_string}")
    print(f"Ciphertext bytes: {ciphertext_bytes}")
    print("###########################################################################################################")
    print()
    return plaintext_string, ciphertext_bytes


def rsa_decryption(ciphertext_bytes, private_key) -> str:
    plaintext_string = RSA.decrypt(ciphertext_bytes, private_key)
    print("###########################################################################################################")
    print("RSA DECRYPTION")
    print("###########################################################################################################")
    print(f"Plaintext string: {plaintext_string}")
    print("###########################################################################################################")
    print()
    return plaintext_string


def message_signing(plaintext_string, private_key) -> bytes | None:
    signature = RSA.sign_message(plaintext_string, private_key)
    print("###########################################################################################################")
    print("MESSAGE SIGNING")
    print("###########################################################################################################")
    print(f"Signature bytes: {signature}")
    print("###########################################################################################################")
    print()
    return signature


def signature_verification(plaintext_string, signature, public_key) -> bool:
    verification = RSA.verify_message(plaintext_string, signature, public_key)
    print("###########################################################################################################")
    print("SIGNATURE VERIFICATION")
    print("###########################################################################################################")
    if verification:
        print("Signature successfully verified.")
    else:
        print("Signature is not valid.")
    print("###########################################################################################################")
    print()
    return verification


def main():
    # NEW KEY PAIR GENERATION
    public_key, private_key = new_key_pair_generation()
    # KEY PAIR EXPORT TO PEM FORMAT
    public_key_pem_format, private_key_pem_format = key_pair_export_to_pem_format(public_key, private_key)
    # KEY PAIR IMPORT FROM PEM FORMAT
    public_key, private_key = key_pair_import_from_pem_format(public_key_pem_format, private_key_pem_format)
    # RSA ENCRYPTION
    plaintext_string, ciphertext_bytes = rsa_encryption(public_key)
    # RSA DECRYPTION
    plaintext_string = rsa_decryption(ciphertext_bytes, private_key)
    # MESSAGE SIGNING
    signature = message_signing(plaintext_string, private_key)
    # SIGNATURE VERIFICATION
    signature_verification(plaintext_string, signature, public_key)


if __name__ == "__main__":
    main()
