from rsa import PublicKey, PrivateKey
from backend.KeyRings import KeyRings
from backend.RSA import RSA


class PGP:
    @staticmethod
    def generate_new_rsa_key_pair() -> tuple[PublicKey, PrivateKey]:
        user_name = input("Please enter your name: ")
        user_email = input("Please enter your email: ")
        key_size_in_bits = int(input("Please enter rsa key size in bits: "))
        private_key_password = input("Please enter your password: ")
        public_key, private_key = RSA.generate_new_key_pair(user_name, user_email, key_size_in_bits, private_key_password)
        return public_key, private_key

    @staticmethod
    def delete_rsa_key_pair_from_private_key_ring():
        user_id = input("Please enter user id: ")
        key_id = int(input("Please enter key id: "))
        private_key_password = input("Please enter your password: ")
        KeyRings.delete_from_private_key_ring(user_id, key_id, private_key_password)

    @staticmethod
    def import_public_key_in_pem_format():
        pass

    @staticmethod
    def export_key_to_pem_format():
        pass

    @staticmethod
    def show_key_rings():
        pass

    @staticmethod
    def send_message():
        pass

    @staticmethod
    def receive_message():
        pass


def main():
    PGP.generate_new_rsa_key_pair()
    # PGP.delete_rsa_key_pair_from_private_key_ring()


if __name__ == "__main__":
    main()
