from datetime import datetime
import json
import os
import base64
from backend.SHA1 import SHA1
from backend.TripleDES import TripleDES


class KeyRings:
    current_script_path = os.path.dirname(__file__)
    key_rings_folder_path = os.path.join(current_script_path, f"files/key_rings")
    private_key_ring_path = f"{key_rings_folder_path}/private_key_ring.json"
    public_key_ring_path = f"{key_rings_folder_path}/public_key_ring.json"

    @staticmethod
    def insert_into_private_key_ring(user_name, user_email, private_key_password, public_key, private_key):
        all_entries = KeyRings.get_all_private_key_ring_entries()
        all_entries.append(KeyRings.create_new_private_key_ring_entry(user_name, user_email, private_key_password, public_key, private_key))
        with open(KeyRings.private_key_ring_path, "w") as file:
            json.dump(all_entries, file, indent=4)

    @staticmethod
    def delete_from_private_key_ring(user_id, key_id, private_key_password):
        all_entries = KeyRings.get_all_private_key_ring_entries()
        modified_entries = []
        for entry in all_entries:
            entry_not_found = not (entry["user_id"] == user_id and entry["key_id"] == key_id)
            if entry_not_found or not KeyRings.is_private_key_password_correct(entry, private_key_password):
                modified_entries.append(entry)
        with open(KeyRings.private_key_ring_path, "w") as file:
            json.dump(modified_entries, file, indent=4)

    @staticmethod
    def is_private_key_password_correct(entry, private_key_password) -> bool:
        encrypted_p = base64.b64decode(entry["private_key"]["encrypted_p"])
        initialization_vector_p = base64.b64decode(entry["private_key"]["initialization_vector_p"])
        encrypted_q = base64.b64decode(entry["private_key"]["encrypted_q"])
        initialization_vector_q = base64.b64decode(entry["private_key"]["initialization_vector_q"])
        key = SHA1.binary_digest(private_key_password)[0:16]  # 128-bit (16 bytes) out of 160-bit SHA1 hash used as TripleDES key
        p = int(TripleDES.decrypt(encrypted_p, initialization_vector_p, key))
        q = int(TripleDES.decrypt(encrypted_q, initialization_vector_q, key))
        return (p * q) == entry["public_key"]["n"]

    @staticmethod
    def get_all_private_key_ring_entries() -> list:
        all_entries = []
        if os.path.exists(KeyRings.private_key_ring_path):
            with open(KeyRings.private_key_ring_path, "r") as file:
                all_entries = json.load(file)
        return all_entries

    @staticmethod
    def create_new_private_key_ring_entry(user_name, user_email, private_key_password, public_key, private_key) -> dict:
        (encrypted_d, initialization_vector_d,
         encrypted_p, initialization_vector_p,
         encrypted_q, initialization_vector_q) = KeyRings.encrypt_private_key(private_key, private_key_password)
        new_entry = {
            "user_id": user_email,
            "key_id": public_key.n % pow(2, 64),
            "timestamp": datetime.now().isoformat(),
            "user_name": user_name,
            "public_key": {
                "n": public_key.n,
                "e": public_key.e
            },
            "private_key": {
                "encrypted_d": base64.b64encode(encrypted_d).decode("utf-8"),
                "initialization_vector_d": base64.b64encode(initialization_vector_d).decode("utf-8"),
                "encrypted_p": base64.b64encode(encrypted_p).decode("utf-8"),
                "initialization_vector_p": base64.b64encode(initialization_vector_p).decode("utf-8"),
                "encrypted_q": base64.b64encode(encrypted_q).decode("utf-8"),
                "initialization_vector_q": base64.b64encode(initialization_vector_q).decode("utf-8")
            }
        }
        return new_entry

    @staticmethod
    def encrypt_private_key(private_key, private_key_password) -> tuple[bytes, bytes, bytes, bytes, bytes, bytes]:
        des3_key = SHA1.binary_digest(private_key_password)[0:16]  # 128-bit (16 bytes) out of 160-bit SHA1 hash used as TripleDES key
        initialization_vector_d, encrypted_d = TripleDES.encrypt(str(private_key.d), des3_key)
        initialization_vector_p, encrypted_p = TripleDES.encrypt(str(private_key.p), des3_key)
        initialization_vector_q, encrypted_q = TripleDES.encrypt(str(private_key.q), des3_key)
        return encrypted_d, initialization_vector_d, encrypted_p, initialization_vector_p, encrypted_q, initialization_vector_q

