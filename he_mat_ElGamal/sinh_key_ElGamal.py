# ...existing code...
from Crypto.PublicKey import ElGamal
import json
import base64
from textwrap import wrap


KEY_LENGTH = 256

key = ElGamal.generate(KEY_LENGTH, None)

public_key = key.publickey()
private_key = key


# Serialize p, g, y into a simple PEM file
pub_components = {
    "p": str(public_key.p),
    "g": str(public_key.g),
    "y": str(public_key.y)
}
b64 = base64.b64encode(json.dumps(pub_components).encode("utf-8")).decode("ascii")
wrapped = "\n".join(wrap(b64, 64))
pem = "-----BEGIN ELGAMAL PUBLIC KEY-----\n" + wrapped + "\n-----END ELGAMAL PUBLIC KEY-----\n"

with open("public-key.pem", "w", encoding="utf-8") as f:
    f.write(pem)

# Serialize private key (p, g, y, x) into a PEM-like file
priv_components = {
    "p": str(private_key.p),
    "g": str(private_key.g),
    "y": str(private_key.y),
    "x": str(private_key.x)
}
b64_priv = base64.b64encode(json.dumps(priv_components).encode("utf-8")).decode("ascii")
wrapped_priv = "\n".join(wrap(b64_priv, 64))
priv_pem = "-----BEGIN ELGAMAL PRIVATE KEY-----\n" + wrapped_priv + "\n-----END ELGAMAL PRIVATE KEY-----\n"

with open("private-key.pem", "w", encoding="utf-8") as f:
    f.write(priv_pem)
