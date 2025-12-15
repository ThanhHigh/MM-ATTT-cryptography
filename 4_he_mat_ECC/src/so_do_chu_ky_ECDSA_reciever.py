from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import base64
from pathlib import Path

PUBLIC_FILE = "public-key.pem"

# --- Example inputs ---
# The sender used plaintext = b'Mid at midnight' when creating the signature.
# Here we verify using the original plaintext and the signature hex printed by the sender.
message_int = 51603167230477137537815295864197256890620973716475416951927373679929936594394
# Replace the string below with the hex string printed by the sender (no 0x prefix):
signature_int = 6951055564709990985454191268262527540063193142089741460519618602868641753796412420605370882867120777651826644687141587350493579096967294368917895404739896

def main():
    key = ECC.import_key(open(PUBLIC_FILE, "rt").read())

    recieved_message = message_int.to_bytes((message_int.bit_length() + 7) // 8, byteorder='big')
    recieved_signature = signature_int.to_bytes((signature_int.bit_length() + 7) // 8, byteorder='big')
    # Compute digest over the original plaintext (not over a hex string of the digest)
    h = SHA256.new(recieved_message)
    verifier = DSS.new(key, "fips-186-3")
    try:
        verifier.verify(h, recieved_signature)
        print("The message is authentic.")
    except ValueError:
        print("The message is not authentic.")


if __name__ == "__main__":
    main()