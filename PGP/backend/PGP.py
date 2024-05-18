from rsa import PublicKey, PrivateKey
from backend.Communication import Communication
from backend.KeyRings import KeyRings
from backend.authentication_algorithms.RSA import RSA


class PGP:
    @staticmethod
    def generate_new_rsa_key_pair(
            person,
            user_name,
            user_email,
            key_size_in_bits,
            private_key_password
    ) -> tuple[PublicKey, PrivateKey]:
        public_key, private_key = RSA.generate_new_key_pair(person, user_name, user_email, key_size_in_bits, private_key_password)
        return public_key, private_key

    @staticmethod
    def get_private_key_ring(person) -> list:
        return KeyRings.get_all_private_key_ring_entries(person)

    @staticmethod
    def get_public_key_ring(person) -> list:
        return KeyRings.get_all_public_key_ring_entries(person)

    @staticmethod
    def delete_rsa_key_pair_from_private_key_ring(
            person_deleting,
            person_affected,
            user_id,
            key_id,
            private_key_password
    ) -> bool:
        return KeyRings.delete_entry_from_private_key_ring(person_deleting, person_affected, user_id, key_id, private_key_password)

    @staticmethod
    def delete_public_key_from_public_key_ring(
            person,
            user_id,
            key_id
    ) -> bool:
        return KeyRings.delete_entry_from_public_key_ring(person, user_id, key_id)

    @staticmethod
    def export_private_key(
            person,
            user_id,
            key_id,
            private_key_password
    ) -> bool:
        return KeyRings.export_private_key(person, user_id, key_id, private_key_password)

    @staticmethod
    def import_private_key(person) -> dict:
        return KeyRings.import_private_key(person)

    @staticmethod
    def export_public_key(person, user_id, key_id) -> bool:
        return KeyRings.export_public_key(person, user_id, key_id)

    @staticmethod
    def import_public_key(import_person, export_person) -> dict:
        return KeyRings.import_public_key(import_person, export_person)

    @staticmethod
    def get_all_private_key_ring_entries(person) -> list:
        return KeyRings.get_all_private_key_ring_entries(person)

    @staticmethod
    def get_all_public_key_ring_entries(person) -> list:
        return KeyRings.get_all_public_key_ring_entries(person)

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
        pgp_message = '{"pgp_message": "eyJwZ3BfbWVzc2FnZSI6IHsibWVzc2FnZV9hbmRfYXV0aGVudGljYXRpb24iOiAiZWRmNmExMzk0ODk2ZjRmY2RlMzBhM2Q1NGVmNTkxYzU4NTk5YTkyYTdkZjMyNTgxYjFmMjkxNWZlNjU1ODIwMjA3M2MxOTVmMDE2YTNiOTk3YmExMjk4ZGRmMzQ2ZWIyYjYyMWNlYTk1MGVhNWUwMDdmYzhjNjNjYWZiZGViZTNiMGU3ZjdlZTA4ZTk2ZTA1OWNlYTU5ZTZjNWY1N2FjNzM2ODg3YzMyMGU2YzQ4ZTUyZTA3MTA3NjUyNWFlZTM1ZGFiMjNmMTk4MTk3YmYxMTExNjIyZWJjYjJhZjY1M2E5ZTZmMmYwNDAyNjkwNDJmMjY3OTU2YmNhOWY3NWVmNTI3N2RiYjc0OTI3ZmM2MjVhYzM5Nzc3YjUzOGEyODQyMWE2OTdiZTg2ZTgyZGY0MGJlZTI4Mjg2M2IyNWVlNmNmMTUyNTk3ZTQ1MzBhMDNlYmYwZDJjYTA4ZGFjMDdlOThkNGNlMjM5ZjMyODIwZWQ2MWU5N2YwZDIyYWEwMDViMjczNDBhNzU0MTFmOGRkZGQ3MDk1OGNlMzY1Y2Y2ODk2ZGExYzY1NTU5ZWQzMTNhYTI5YjQxMTJlNmE0NDhmOTUzNWJjN2QzMmMxYmFhNDRlNzZiNTA1YjMzMzE3ZmI2YWM3MDExZWNmNmYxODE2OGYzODc0MjdmZmEwNWY2NmMzMjYwMjNkNTlmYjdjY2ZhMjkyNDU3MTFmYmIwYjE5MmE0MTEyZDI5MDE5YWYwNjk4ZTE0ZTBhMTQzMDZlYjYxY2VmODRkYWE5MWU1MWNmZTMwNGQxMjk2NDEwMjJjMmFkOTkxOTA1YjViZDI2NDQ0MGZlOGZmNGFiYWFhOTQ5YWI3MTk2YTc4NDdmNDhkNDNiYjliMjkwN2E2NjJhN2QyMmQ1MDgyMzBiZjI3YWI0ODZhODBjNjY3YTlmMDIwNGNkOGQ5ZGJkYzkwNTJjNzU3YWYwYjMxMTkyMWNhYjRhMCIsICJjb25maWRlbnRpYWxpdHkiOiB7InNlc3Npb25fa2V5IjogIjdjOTdhNzJmNzdiZTFiNjE0OWJjZDNmMTkzZDUyOWIzMzdmZmI1ZTU4NTZlMDc3MjY1MDNhYzhmZWU3ZjZlMmU1MjFhMTAxODJlOTg3NmFhZjBlNjQ3MTJmODllN2VkNmQ5YWY4MDg1MDBmZWQzMDAzYTA4MTZlYTdiZTNiYThhZmZkZjhmMGU5ZjI3ODBmMDU5ZGYyZDVhZWJmZTNkNDkzMzliYzk0MTEyNjdmMGM3Yjk4NzYwMjAzMWM3NmJmOTBhNjliNWE2MDZhM2UwY2FkOTQ5YTllNjU3ZjE2ZDBhMDUyM2NiODkwY2E5ZTQwYmE3NzI4ZjZjNTc3NWVlMjUiLCAicmVjZWl2ZXJfcHVibGljX2tleV9pZCI6ICIzOTkzNzc1NDI2MDA2NTYwNjgzIiwgImFsZ29yaXRobSI6ICJBRVMxMjgiLCAiaW5pdGlhbGl6YXRpb25fdmVjdG9yIjogIjg2ZmI3NmM3MTkzYTBlMmFlOGY4ZjZmN2RhNmI2M2Q3In19LCAiaXNfc2lnbmVkIjogdHJ1ZSwgImlzX2NvbXByZXNzZWQiOiB0cnVlLCAiaXNfZW5jcnlwdGVkIjogdHJ1ZSwgImlzX3JhZGl4NjRfZW5jb2RlZCI6IHRydWV9", "is_signed": true, "is_compressed": true, "is_encrypted": true, "is_radix64_encoded": true}'
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
    # PGP.receive_message()
    pass


if __name__ == "__main__":
    main()
