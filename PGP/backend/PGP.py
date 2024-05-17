from rsa import PublicKey, PrivateKey
from backend.Communication import Communication
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
        key_id = input("Please enter key id: ")
        private_key_password = input("Please enter your password: ")
        KeyRings.delete_entry_from_private_key_ring(person_deleting, person_affected, user_id, key_id, private_key_password)

    @staticmethod
    def export_public_key():
        person = input("Please enter which person you are (A or B): ")
        user_id = input("Please enter user id: ")
        key_id = input("Please enter key id: ")
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
        key_id = input("Please enter key id: ")
        KeyRings.delete_entry_from_public_key_ring(person, user_id, key_id)

    @staticmethod
    def export_private_key():
        person = input("Please enter which person you are (A or B): ")
        user_id = input("Please enter user id: ")
        key_id = input("Please enter key id: ")
        KeyRings.export_private_key(person, user_id, key_id)

    @staticmethod
    def import_private_key():
        person = input("Please enter which person you are (A or B): ")
        KeyRings.import_private_key(person)

    @staticmethod
    def send_message():
        message = input("Please enter your message: ")
        sender = input("Please enter who is sending the message (A or B): ")
        receiver = input("Please enter who is receiving the message (A or B): ")
        authentication = bool(input("Authentication: "))
        compression = bool(input("Compression: "))
        confidentiality = bool(input("Confidentiality: "))
        radix64 = bool(input("Radix-64: "))
        Communication.send_message(message, sender, receiver, authentication, compression, confidentiality, radix64)

    @staticmethod
    def receive_message():
        receiver = input("Please enter who is receiving the message (A or B): ")
        pgp_message = '{"pgp_message": "eyJwZ3BfbWVzc2FnZSI6IHsibWVzc2FnZV9hbmRfYXV0aGVudGljYXRpb24iOiAiMzcwMmY5M2M0N2U2ZjFkZWVmNjhiYjk4NDc2NWNhMjUxYThhNDIyY2UwNDNhYTM5YTFlYjhiNTlhMmJmMDY0Y2VmMTE3ZjIxYTU4YzExZmMwNmY5YjhiMWExZTRlNDQ4OTQwZjdmODM4NTcwNWI5YjJlMzMzMzZlYTk0NWY1ZTA1NDM3NGI1ZWJlZTBlNTRkZThjOTgwM2QwYWFiMDY2Y2U1MTgzNTg4YWVmZjU0MzNmMTI4NmEzM2E0M2YwMTQ4NDRiZjVmZWVmZWVlZjE1NWQxZDU4N2Q0NGVkN2RhNjFmZDRiNzQ5Y2ZlMjMyNmJlMjc4NmJhYzlmY2M0ODEyY2I1ZWI0Zjg0N2FlMTBiNWM5YzM2MTA0NjU4NGM5OTJmMzhhZTBmMTBlNzk2MDRkZDRjNDkzMmU4ZDE0MmQ4YWQ4MzRjN2Q1N2I5M2VjNWY2YTRjZDY3MzYxYTE2ZDg1YjBhYjJmMDgyZDk3ZjA0MzE4MWI1ODVlOWZkOWVmMzZmNzcyYTllMmQ1YjYzOTNhNDgxMThhODc0ZDQxZDBjMDk3ZDE4ZjE2ZWFiZjA5ZTg1NDljYzFhNmI2ODZjNDhkOWVkZWE3ZDQ5ZGVjMjY0OGJlNzhlNjczZWM1MDY4YTFjM2U5MzMxODc1YmI3NDEyYzc1NWQ4ZGJmNjg4OWEyMzQxZjg5MjI2MTliZTZjOWU5Y2Y2M2ViZjE0ZDlhYjUzNDg5ZThjM2U2YTdiZjE0ZWNlNTllMmI3MzFiM2FmZGE1MmM0OTU0Nzg3MmEzZThjYmY3MzVkYzJmN2U0M2U2ZTAxZTcxYmUwMGY4OGZhM2VjZjhkZThmYzI5NDk5YzVkMzUzMmZiMzMzYzVhNmJlM2IyMWNlNmM1NTNiOTY5ODVlYTJiODkyM2ZjOGI5MDZjMTUxMzFiNmY5MDQ2YjMyY2EiLCAiY29uZmlkZW50aWFsaXR5IjogeyJzZXNzaW9uX2tleSI6ICIzNmExNTk3NWZmNjNiOTU4Y2YzMGM0NzFjOGZkNDllZDk2MDViY2NmZTA0ODhhNjNkMDEzNzgwZGE5ZGFmMGJjMjNjODg1M2VhOTYyNTAyNjk1YzliNTgwMmZkZDdiMzVkMWFiNmFkZGViMTg1Y2RkYzI2YmU0ZGZlOWNiZWY1ZDdmYmZmOWQyOTMzZWFlOTgyNTMyM2U0MjY0MzA2M2EzNjk3OThhMjI1YTM0NjM2YTgzODBjODBiMTcwODE3NTlmMTg3NzBjNDFmMWFkMzg1ODJmZTE5YThkNmNiYWZlMWJkOWMzNDk3ODg0YTViMzgzYjcwMGMxYzg0ZWFjMzg1IiwgInJlY2VpdmVyX3B1YmxpY19rZXlfaWQiOiAiMzk5Mzc3NTQyNjAwNjU2MDY4MyIsICJhbGdvcml0aG0iOiAiVHJpcGxlREVTIiwgImluaXRpYWxpemF0aW9uX3ZlY3RvciI6ICJmNTgyYzY3MDdjNGY2NDMxIn19LCAiaXNfc2lnbmVkIjogdHJ1ZSwgImlzX2NvbXByZXNzZWQiOiB0cnVlLCAiaXNfZW5jcnlwdGVkIjogdHJ1ZSwgImlzX3JhZGl4NjRfZW5jb2RlZCI6IHRydWV9", "is_signed": true, "is_compressed": true, "is_encrypted": true, "is_radix64_encoded": true}'
        Communication.receive_message(receiver, pgp_message)


def main():
    # PGP.generate_new_rsa_key_pair()
    # PGP.delete_rsa_key_pair_from_private_key_ring()
    # PGP.export_public_key()
    # PGP.import_public_key()
    # PGP.delete_public_key_from_public_key_ring()
    # PGP.export_private_key()
    # PGP.import_private_key()
    # PGP.send_message()
    PGP.receive_message()


if __name__ == "__main__":
    main()
