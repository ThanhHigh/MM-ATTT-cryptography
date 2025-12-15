from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


PRIVATE_FILE = "private-key.pem"
PUBLIC_FILE = "public-key.pem"

if __name__ == "__main__":

    with open(PRIVATE_FILE, "rt") as f:
        data = f.read()
        print(data)
        private_key = ECC.import_key(data)
        
    print(private_key.d)

    with open(PUBLIC_FILE, "rt") as f:
        data2 = f.read()
        print(data2)
        public_key = ECC.import_key(data2)
        print(public_key)

    plaintext = b'Mid at midnight'
    h = SHA256.new(plaintext)
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(h)

    message_int = int.from_bytes(h.digest(), byteorder='big')
    print("Message (int):", message_int)
    
    signature_int = int.from_bytes(signature, byteorder='big')
    print("Signature (int):", signature_int)

    # debug
    with open(PUBLIC_FILE, "rt") as f:
        p
    
    verifier = DSS.new(public_key, "fips-186-3")
    try:
        verifier.verify(h, signature)
        print("The message is authentic.")
    except ValueError:
        print("The message is not authentic.")
