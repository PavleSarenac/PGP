import hashlib


class SHA1:
    @staticmethod
    def hex_digest(message_string) -> str:
        sha1 = hashlib.sha1()
        message_bytes = message_string.encode("utf-8")
        sha1.update(message_bytes)
        return sha1.hexdigest()

    @staticmethod
    def binary_digest(message_string) -> bytes:
        sha1 = hashlib.sha1()
        message_bytes = message_string.encode("utf-8")
        sha1.update(message_bytes)
        return sha1.digest()
