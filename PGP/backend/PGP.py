class PGP:
    @staticmethod
    def generate_new_and_delete_existing_key_pair():
        user_name = input("Please enter your name: ")
        user_email = input("Please enter your email: ")
        rsa_key_size_in_bits = int(input("Please enter rsa key size in bits: "))
        user_password = input("Please enter your password: ")

    @staticmethod
    def import_key_in_pem_format():
        pass

    @staticmethod
    def export_key_in_pem_format():
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


if __name__ == "__main__":
    PGP.generate_new_and_delete_existing_key_pair()