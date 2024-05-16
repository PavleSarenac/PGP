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
        pgp_message = "eyJtZXNzYWdlX2FuZF9hdXRoZW50aWNhdGlvbiI6ICI0YTAyZDg1ZTFmOTZjMTc4ZTk3NjFhZGZiMDY0ODFkMGZlNDdhM2U3MTY4YzczZmI5MjE2MTUxMGYwMWNlZDc1NzYwMjBlNTc1M2YwMDZkOGJjNWQwZGJiYjZmMDQ2MzQ0Njg1N2IyNzgxYmVjZTU2YjBmOTk2ODYxODc2NzkxYjkwZDVmNzMwY2Q0ZTNjODI3YmRjYTNjNTEyNTA5YzAwNjg1YzkwMDVhZTYwMjQ0OGEzYzUzNTlkNzk1ZTEzNGYxNzdlMGY3ZjdkYTVjZjc5MTdhM2Q2YzllYjBkNmFkYTk3ZDNhZTE0N2VmYmFiNGMyOTIxNGI3ZjdiYmU1M2U3ZTI2YjJhNmJlMzFiYTc4MjcwNzk4YzA4Mzg0N2IwMmM1OTg1YWUzZTQ0Njc2ZjVjZmU0ZDFlNDAzY2EyMDU0NmRmOWJmNmY3ZjQzNDNiNDRhMzEyMDA0MDY1MWNhMTRlYTQxNmU4OTc1MjAxZTIwNTRkMGY1MDI4MzM1ZTU0NGViODZjNzEyOWM1Y2Y2M2I3ZmVmMDE0M2ZhODc1MzcwY2M0NzhhM2JhYWQ1NGE4Y2Q5ODQ2MGM1NGM1MTc2NmZjZTJjODk3ZWIyNmI0NDEwYjU0YTNkOWYyOWUzODUyNTUzZDc5YzRiNjIzYzAxZDJhY2RjZWJjOTcxZTBmMDRiYjQyYWE5ZTE2NDc0NzEwYmRhNWMxMWExNGIzMWFhMWU0ZWI1MDNlZjU3YzU2YzA5ZDYxNDhkNGY1ODQwODY3NTcwZmMzMGZiMTgyODUzMzNlYzFlNDg4ZWJjYTM3ZThjZTkwYzllMmFjZTIxYTVkN2M3OWRjOTNiMzA2NTY2NTk0ZjU3NjY1NGUzNzFkZjcwMWY5Mzk2YjhlYmEwYTRmNjgxN2M0NTFmODAwYjMyNzc0M2FiN2U3MjViZmMyNjIwOWI1OTIyMWE5NzkyMzYwZDExNWJiOWZhOWU4NDdhMTIxIiwgImNvbmZpZGVudGlhbGl0eSI6IHsic2Vzc2lvbl9rZXkiOiAiNTk1ZDRmOGRjM2NjNjMwMDNkNDg2Y2JiZTVjMjk3MDkwZjNhMzY4YjBmMGE4ZDZmZDk0NDliZjkxNzJlYjc3MDc1YmRmN2ExZDg5YTQ1MzBhMjZhMjM1Yjk3MWRjZmI3YzkzZDA1ZjI5MmMxN2ZkNjE5OGFlMThjYmU3N2VkYjY2NjE1ZTMxODAxNmNlOTQ1ZmY2YWVlYjM2OWQ3YzNjYTVmZmQ4OTA3NTc5YzQ3NDRjNzg4OTM4ZDJmNzJmYzYwNGIxOWFjYTRlYzEyNjJkNjE0ZTJhZTEzMTAwZTI4YjllNzFlZWNmMDg3MTM4YTA1OTkxMjUyMjQyZTg0OWJhZSIsICJyZWNlaXZlcl9wdWJsaWNfa2V5X2lkIjogIjM5OTM3NzU0MjYwMDY1NjA2ODMiLCAiYWxnb3JpdGhtIjogIkFFUzEyOCIsICJpbml0aWFsaXphdGlvbl92ZWN0b3IiOiAiMGNmOGRiZDk2YjYwNTE5NjUxNjQ4ZWMzMThjOTY2N2EifSwgImlzX3NpZ25lZCI6IHRydWUsICJpc19jb21wcmVzc2VkIjogdHJ1ZSwgImlzX2VuY3J5cHRlZCI6IHRydWUsICJpc19yYWRpeDY0X2VuY29kZWQiOiB0cnVlfQ=="
        Communication.receive_message(receiver, pgp_message)


def main():
    # PGP.generate_new_rsa_key_pair()
    # PGP.delete_rsa_key_pair_from_private_key_ring()
    # PGP.export_public_key()
    # PGP.import_public_key()
    # PGP.delete_public_key_from_public_key_ring()
    # PGP.export_private_key()
    # PGP.import_private_key()
    PGP.send_message()


if __name__ == "__main__":
    main()
