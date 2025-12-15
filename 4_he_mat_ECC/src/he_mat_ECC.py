from Crypto.PublicKey import ECC

PUBLIC_FILE = "public-key.pem"
PRIVATE_FILE = "private-key.pem"

if __name__ == "__main__":

    with open(PRIVATE_FILE, "rt") as f:
        private_key = ECC.import_key(f.read())
    with open(PUBLIC_FILE, "rt") as f:
        public_key = ECC.import_key(f.read())

    # test
    print("Private Key:")
    print(private_key)
    print("Public Key:")
    print(public_key)

    plaintext = b'Mid at midnight'
    