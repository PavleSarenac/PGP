import base64

from backend.KeyRings import KeyRings
from datetime import datetime
from backend.authentication_algorithms.RSA import RSA
from backend.authentication_algorithms.SHA1 import SHA1
import zlib
import json
from Crypto.Random import get_random_bytes
from backend.confidentiality_algorithms.AES128 import AES128
from backend.confidentiality_algorithms.TripleDES import TripleDES


class Communication:
    @staticmethod
    def send_message(plaintext, sender, receiver, authentication, compression, confidentiality, radix64) -> str:
        pgp_message = {
            "message_and_authentication": {
                "message": {
                    "data": plaintext,
                    "timestamp": datetime.now().isoformat(),
                    "filename": "plaintext.txt"
                },
                "authentication": dict()
            },
            "confidentiality": dict()
        }

        if authentication:
            sender_rsa_key_user_id = input("Please enter user id (authentication): ")
            sender_rsa_key_id = input("Please enter key id (authentication): ")
            private_key_password = input("Please enter your password (authentication): ")
            sender_private_key = KeyRings.get_private_key(sender, sender_rsa_key_user_id, sender_rsa_key_id, private_key_password)
            pgp_message["message_and_authentication"]["authentication"] = Communication.authenticate_message(plaintext, sender_rsa_key_id, sender_private_key)

        if compression:
            pgp_message["message_and_authentication"] = Communication.compress_dictionary(pgp_message["message_and_authentication"])

        if confidentiality:
            session_key = get_random_bytes(16)  # Session key is always 128-bit (both for AES128 and TripleDES)
            receiver_rsa_user_id = input("Please enter user id (confidentiality): ")
            receiver_rsa_key_id = input("Please enter key id (confidentiality): ")
            receiver_public_key = KeyRings.get_public_key(sender, receiver_rsa_user_id, receiver_rsa_key_id)
            confidentiality_algorithm = input("Please enter confidentiality algorithm: ")
            pgp_message["confidentiality"] = Communication.encrypt_message_and_signature(pgp_message, session_key, receiver_rsa_key_id, receiver_public_key, confidentiality_algorithm)

        pgp_message = json.dumps(pgp_message)
        if radix64:
            pgp_message = Communication.get_radix64_encoded_pgp_message(pgp_message)

        pgp_message = {
            "pgp_message": pgp_message,
            "is_signed": authentication,
            "is_compressed": compression,
            "is_encrypted": confidentiality,
            "is_radix64_encoded": radix64
        }
        return json.dumps(pgp_message)

    @staticmethod
    def receive_message(receiver, pgp_message):
        pgp_message = json.loads(pgp_message)

        if pgp_message["is_radix64_encoded"]:
            pgp_message["pgp_message"] = Communication.get_pgp_message_from_radix64_encoded_pgp_message(pgp_message["pgp_message"])
        pgp_message["pgp_message"] = json.loads(pgp_message["pgp_message"])

    @staticmethod
    def authenticate_message(message, sender_rsa_key_id, sender_private_key) -> dict:
        timestamp = datetime.now().isoformat()
        message_digest = SHA1.binary_digest(message + timestamp)
        leading_two_octets_message_digest = message_digest[0:2]
        signed_message_digest = RSA.sign_message(message_digest, sender_private_key)
        return {
            "signed_message_digest": signed_message_digest.hex(),
            "leading_two_octets_message_digest": leading_two_octets_message_digest.hex(),
            "sender_public_key_id": sender_rsa_key_id,
            "timestamp": timestamp
        }

    @staticmethod
    def compress_dictionary(dictionary) -> bytes:
        dictionary_string = json.dumps(dictionary)
        dictionary_bytes = dictionary_string.encode("utf-8")
        dictionary_compressed = zlib.compress(dictionary_bytes)
        return dictionary_compressed

    @staticmethod
    def encrypt_message_and_signature(pgp_message, session_key, receiver_rsa_key_id, receiver_public_key, confidentiality_algorithm) -> dict:
        encrypted_message_and_authentication = None
        initialization_vector = None
        if confidentiality_algorithm == "AES128":
            initialization_vector, encrypted_message_and_authentication = AES128.encrypt(pgp_message["message_and_authentication"], session_key)
        elif confidentiality_algorithm == "TripleDES":
            initialization_vector, encrypted_message_and_authentication = TripleDES.encrypt(pgp_message["message_and_authentication"], session_key)
        pgp_message["message_and_authentication"] = encrypted_message_and_authentication.hex()
        encrypted_session_key = RSA.encrypt(session_key, receiver_public_key)
        return {
            "session_key": encrypted_session_key.hex(),
            "receiver_public_key_id": receiver_rsa_key_id,
            "algorithm": confidentiality_algorithm,
            "initialization_vector": initialization_vector.hex()
        }

    @staticmethod
    def get_radix64_encoded_pgp_message(pgp_message_json_string) -> str:
        pgp_message_bytes = pgp_message_json_string.encode("utf-8")
        return base64.b64encode(pgp_message_bytes).decode("utf-8")

    @staticmethod
    def get_pgp_message_from_radix64_encoded_pgp_message(radix64_encoded_pgp_message) -> str:
        pgp_message_bytes = base64.b64decode(radix64_encoded_pgp_message)
        return pgp_message_bytes.decode("utf-8")
