#GEN new ECC key
from Crypto.PublicKey import ECC

PUBLIC_FILE_PEM = "public-key.pem"
PRIVATE_FILE_PEM = "private-key.pem"
PUBLIC_FILE_DER = "public-key.der"
PRIVATE_FILE_DER = "private-key.der"

eccKey = ECC.generate(curve='P-256')

with open(PUBLIC_FILE_PEM, "wt") as f:
    f.write(eccKey.public_key().export_key(format="PEM"))

with open(PRIVATE_FILE_PEM, "wt") as f:
    f.write(eccKey.export_key(format="PEM"))

