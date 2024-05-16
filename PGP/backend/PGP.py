from rsa import PublicKey, PrivateKey
from backend.KeyRings import KeyRings
from backend.authentication_algorithms.RSA import RSA


class PGP:
    @staticmethod
    def generate_new_rsa_key_pair() -> tuple[PublicKey, PrivateKey]:
        person = input("Please enter which person you are (A or B): ")
        user_name = input("Please enter your name: ")
        user_email = input("Please enter your email: ")
        key_size_in_bits = int(input("Please enter rsa key size in bits: "))
        private_key_password = input("Please enter your password: ")
        public_key, private_key = RSA.generate_new_key_pair(person, user_name, user_email, key_size_in_bits, private_key_password)
        return public_key, private_key

    @staticmethod
    def delete_rsa_key_pair_from_private_key_ring():
        person_deleting = input("Please enter who is deleting the private key (A or B): ")
        person_affected = input("Please enter who is affected by the deletion of private key (A or B): ")
        user_id = input("Please enter user id: ")
        key_id = int(input("Please enter key id: "))
        private_key_password = input("Please enter your password: ")
        KeyRings.delete_entry_from_private_key_ring(person_deleting, person_affected, user_id, key_id, private_key_password)

    @staticmethod
    def export_public_key():
        person = input("Please enter which person you are (A or B): ")
        user_id = input("Please enter user id: ")
        key_id = int(input("Please enter key id: "))
        KeyRings.export_public_key(person, user_id, key_id)

    @staticmethod
    def import_public_key():
        import_person = input("Please enter who is importing the key (A or B): ")
        export_person = input("Please enter who is exporting the key (A or B): ")
        KeyRings.import_public_key(import_person, export_person)

    @staticmethod
    def delete_public_key_from_public_key_ring():
        person = input("Please enter which person you are (A or B): ")
        user_id = input("Please enter user id: ")
        key_id = int(input("Please enter key id: "))
        KeyRings.delete_entry_from_public_key_ring(person, user_id, key_id)

    @staticmethod
    def export_private_key():
        person = input("Please enter which person you are (A or B): ")
        user_id = input("Please enter user id: ")
        key_id = int(input("Please enter key id: "))
        KeyRings.export_private_key(person, user_id, key_id)

    @staticmethod
    def import_private_key():
        person = input("Please enter which person you are (A or B): ")
        KeyRings.import_private_key(person)

    @staticmethod
    def send_message():
        sender = input("Please enter who is sending the message (A or B): ")
        receiver = input("Please enter who is receiving the message (A or B): ")
        authentication = bool(input("Authentication: "))
        compression = bool(input("Compression: "))
        confidentiality = bool(input("Confidentiality: "))
        radix64 = bool(input("Radix-64: "))

    @staticmethod
    def receive_message():
        pass


def main():
    # PGP.generate_new_rsa_key_pair()
    PGP.delete_rsa_key_pair_from_private_key_ring()
    # PGP.export_public_key()
    # PGP.import_public_key()
    # PGP.delete_public_key_from_public_key_ring()
    # PGP.export_private_key()
    # PGP.import_private_key()


if __name__ == "__main__":
    main()
