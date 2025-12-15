from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

message = b'1204041900191208031308060719'
key = RSA.import_key(open('private-key.pem').read())
h = SHA256.new(message)
h_int = int.from_bytes(h.digest(), byteorder='big')
print("Message hash (int):", h_int)
signature = pkcs1_15.new(key).sign(h)
signature_int = int.from_bytes(signature, byteorder='big')
print("Signature (int):", signature_int)