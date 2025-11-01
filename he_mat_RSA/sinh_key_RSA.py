from Crypto.PublicKey import RSA

PUBLIC_FILE = "public-key.pem"
PRIVATE_FILE = "private-key.pem"
BIT_LENGTH = 1024

if __name__ == "__main__":
	key = RSA.generate(BIT_LENGTH)
	private_pem = key.export_key(format="PEM")
	public_pem = key.publickey().export_key(format="PEM")

	with open(PRIVATE_FILE, "wb") as f:
		f.write(private_pem)
	with open(PUBLIC_FILE, "wb") as f:
		f.write(public_pem)