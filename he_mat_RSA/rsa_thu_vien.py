import rsa

# public_key, private_key = rsa.newkeys(1024)
# with open('public_key.pem', 'wb') as pub_file:
#     pub_file.write(public_key.save_pkcs1('PEM'))
# with open('private_key.pem', 'wb') as priv_file:
#     priv_file.write(private_key.save_pkcs1('PEM'))

with open('public_key.pem', 'rb') as pub_file:
    public_key = rsa.PublicKey.load_pkcs1(pub_file.read())
with open('private_key.pem', 'rb') as priv_file:
    private_key = rsa.PrivateKey.load_pkcs1(priv_file.read())

message = "Meet at midnight"

# encrypted_message = rsa.encrypt(message.encode(), public_key)
# with open('encrypted_message.bin', 'wb') as enc_file:
#     enc_file.write(encrypted_message)
encrypted_message = open('encrypted_message.bin', 'rb').read()
print('Encrypted message:', encrypted_message)
plain_message = rsa.decrypt(encrypted_message, private_key).decode()

print('Decrypted message:', plain_message)


print (public_key)
print (private_key)