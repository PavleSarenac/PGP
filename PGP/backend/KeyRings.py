from datetime import datetime
import json
import os

from backend.SHA1 import SHA1
from backend.TripleDES import TripleDES


class KeyRings:
    current_script_path = os.path.dirname(__file__)
    key_rings_folder_path = os.path.join(current_script_path, f"files/key_rings")
    private_key_ring_path = f"{key_rings_folder_path}/private_key_ring.json"
    public_key_ring_path = f"{key_rings_folder_path}/public_key_ring.json"

    @staticmethod
    def insert_into_private_key_ring(user_name, user_email, private_key_password, public_key, private_key):
        all_entries = KeyRings.get_all_entries()
        all_entries.append(KeyRings.create_new_entry(user_name, user_email, private_key_password, public_key, private_key))
        with open(KeyRings.private_key_ring_path, "w") as file:
            json.dump(all_entries, file, indent=4)

    @staticmethod
    def get_all_entries() -> list:
        all_entries = []
        if os.path.exists(KeyRings.private_key_ring_path):
            with open(KeyRings.private_key_ring_path, "r") as file:
                all_entries = json.load(file)
        return all_entries

    @staticmethod
    def create_new_entry(user_name, user_email, private_key_password, public_key, private_key) -> dict:
        new_entry = {
            "user_id": user_email,
            "key_id": public_key.n % pow(2, 64),
            "timestamp": datetime.now().isoformat(),
            "user_name": user_name,
            "public_key_data": {
                "n": public_key.n,
                "e": public_key.e
            },
            "encrypted_private_key_data": {
                "d": "",
                "initialization_vector_d": "",
                "p": private_key.p,
                "q": private_key.q
            }
        }
        return new_entry

    @staticmethod
    def encrypt_private_key(private_key, private_key_password):
        des3_key = SHA1.binary_digest(private_key_password)
        encrypted_d, initialization_vector_d = TripleDES.encrypt(str(private_key.d), )

