from backend.SHA1 import SHA1


def hash_generation():
    input_string = "Hello world!"
    sha1_digest = SHA1.binary_digest(input_string)
    print("###########################################################################################################")
    print("HASH GENERATION")
    print("###########################################################################################################")
    print(f"Input string: {input_string}")
    print(f"SHA-1 digest: {sha1_digest}")
    print("###########################################################################################################")
    print()


def test_SHA1():
    # HASH GENERATION
    hash_generation()


def main():
    test_SHA1()


if __name__ == "__main__":
    main()
