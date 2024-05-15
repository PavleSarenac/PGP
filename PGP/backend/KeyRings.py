from datetime import datetime
import json
import os
import base64
from backend.SHA1 import SHA1
from backend.TripleDES import TripleDES
from rsa import PublicKey, PrivateKey


class KeyRings:
    current_script_path = os.path.dirname(__file__)
    paths = {
        "a": {
            "private_key_ring_path": os.path.join(current_script_path, f"files/person_a/key_rings/private_key_ring.json"),
            "public_key_ring_path": os.path.join(current_script_path, f"files/person_a/key_rings/public_key_ring.json")
        },
        "b": {
            "private_key_ring_path": os.path.join(current_script_path, f"files/person_b/key_rings/private_key_ring.json"),
            "public_key_ring_path": os.path.join(current_script_path, f"files/person_b/key_rings/public_key_ring.json")
        }
    }

    @staticmethod
    def insert_into_private_key_ring(person, user_name, user_email, private_key_password, public_key, private_key):
        all_entries = KeyRings.get_all_private_key_ring_entries(person)
        all_entries.append(KeyRings.create_new_private_key_ring_entry(user_name, user_email, private_key_password, public_key, private_key))
        with open(KeyRings.paths[person.lower()]["private_key_ring_path"], "w") as file:
            json.dump(all_entries, file, indent=4)

    @staticmethod
    def insert_into_public_key_ring(import_person, export_person, user_id, key_id):
        all_export_person_private_key_ring_entries = KeyRings.get_all_private_key_ring_entries(export_person)
        all_import_person_public_key_ring_entries = KeyRings.get_all_public_key_ring_entries(import_person)
        for entry in all_export_person_private_key_ring_entries:
            if entry["user_id"] == user_id and entry["key_id"] == key_id:
                all_import_person_public_key_ring_entries.append(KeyRings.create_new_public_key_ring_entry(entry))
                break
        with open(KeyRings.paths[import_person.lower()]["public_key_ring_path"], "w") as file:
            json.dump(all_import_person_public_key_ring_entries, file, indent=4)

    @staticmethod
    def delete_entry_from_private_key_ring(person, user_id, key_id, private_key_password):
        all_entries = KeyRings.get_all_private_key_ring_entries(person)
        modified_entries = []
        for entry in all_entries:
            entry_not_found = not (entry["user_id"] == user_id and entry["key_id"] == key_id)
            if entry_not_found or not KeyRings.is_private_key_password_correct(entry, private_key_password):
                modified_entries.append(entry)
        with open(KeyRings.paths[person.lower()]["private_key_ring_path"], "w") as file:
            json.dump(modified_entries, file, indent=4)

    @staticmethod
    def delete_entry_from_public_key_ring(person, user_id, key_id):
        pass

    @staticmethod
    def is_private_key_password_correct(entry, private_key_password) -> bool:
        try:
            encrypted_private_key_pem_format = base64.b64decode(entry["private_key_pem_format"]["encrypted_private_key_pem_format"])
            initialization_vector = base64.b64decode(entry["private_key_pem_format"]["initialization_vector"])
            key = SHA1.binary_digest(private_key_password)[0:16]  # 128-bit (16 bytes) out of 160-bit SHA1 hash used as TripleDES key
            private_key_pem_format = TripleDES.decrypt(encrypted_private_key_pem_format, initialization_vector, key)
            private_key = KeyRings.import_private_key_from_pem_format(private_key_pem_format)
            public_key_pem_format = base64.b64decode(entry["public_key_pem_format"])
            public_key = KeyRings.import_public_key_from_pem_format(public_key_pem_format)
        except ValueError:
            return False
        return (private_key.p * private_key.q) == public_key.n

    @staticmethod
    def get_all_private_key_ring_entries(person) -> list:
        all_entries = []
        if os.path.exists(KeyRings.paths[person.lower()]["private_key_ring_path"]):
            with open(KeyRings.paths[person.lower()]["private_key_ring_path"], "r") as file:
                all_entries = json.load(file)
        return all_entries

    @staticmethod
    def get_all_public_key_ring_entries(person) -> list:
        all_entries = []
        if os.path.exists(KeyRings.paths[person.lower()]["public_key_ring_path"]):
            with open(KeyRings.paths[person.lower()]["public_key_ring_path"], "r") as file:
                all_entries = json.load(file)
        return all_entries

    @staticmethod
    def create_new_private_key_ring_entry(user_name, user_email, private_key_password, public_key, private_key) -> dict:
        initialization_vector, encrypted_private_key_pem_format = KeyRings.encrypt_private_key(private_key, private_key_password)
        new_entry = {
            "user_id": user_email,
            "key_id": public_key.n % pow(2, 64),
            "timestamp": datetime.now().isoformat(),
            "user_name": user_name,
            "public_key_pem_format": base64.b64encode(KeyRings.export_key_to_pem_format(public_key)).decode("utf-8"),
            "private_key_pem_format": {
                "encrypted_private_key_pem_format": base64.b64encode(encrypted_private_key_pem_format).decode("utf-8"),
                "initialization_vector": base64.b64encode(initialization_vector).decode("utf-8")
            }
        }
        return new_entry

    @staticmethod
    def create_new_public_key_ring_entry(export_person_private_key_ring_entry):
        new_entry = {
            "user_id": export_person_private_key_ring_entry["user_id"],
            "key_id": export_person_private_key_ring_entry["key_id"],
            "timestamp": datetime.now().isoformat(),
            "user_name": export_person_private_key_ring_entry["user_name"],
            "public_key_pem_format": export_person_private_key_ring_entry["public_key_pem_format"]
        }
        return new_entry

    @staticmethod
    def encrypt_private_key(private_key, private_key_password) -> tuple[bytes, bytes]:
        des3_key = SHA1.binary_digest(private_key_password)[0:16]  # 128-bit (16 bytes) out of 160-bit SHA1 hash used as TripleDES key
        private_key_pem_format = KeyRings.export_key_to_pem_format(private_key)
        initialization_vector, encrypted_private_key_pem_format = TripleDES.encrypt(private_key_pem_format, des3_key)
        return initialization_vector, encrypted_private_key_pem_format

    @staticmethod
    def export_key_to_pem_format(key) -> bytes:
        return key.save_pkcs1(format="PEM")

    @staticmethod
    def import_public_key_from_pem_format(public_key_bytes) -> PublicKey:
        return PublicKey.load_pkcs1(keyfile=public_key_bytes, format="PEM")

    @staticmethod
    def import_private_key_from_pem_format(private_key_bytes) -> PrivateKey:
        return PrivateKey.load_pkcs1(keyfile=private_key_bytes, format="PEM")

