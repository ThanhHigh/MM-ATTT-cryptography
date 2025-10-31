from Crypto.Util import number
from Crypto.Hash import SHA256

def generate_p_g(bits):
    # Chọn số nguyên tố p có độ dài bits
    p = number.getPrime(bits)

    # Chọn một số nguyên tố g
    g = number.getPrime(bits - 1)

    return p, g

def generate_keypair(bits):
    p, g = generate_p_g(bits)

    # Chọn số ngẫu nhiên a
    a = number.getRandomRange(2, p-2)

    # Tính A = g^a mod p
    A = pow(g, a, p)

    # Khóa công khai là (p, g, A), khóa bí mật là a
    public_key = (p, g, A)
    private_key = a
    return public_key, private_key

def encrypt(public_key, plaintext):
    p, g, A = public_key

    # Chọn số ngẫu nhiên k
    k = number.getRandomRange(2, p-2)

    # Tính B = g^k mod p và s = A^k * plaintext mod p
    B = pow(g, k, p)
    s = (pow(A, k, p) * plaintext) % p

    # Bản mã là cặp (B, s)
    ciphertext = (B, s)
    return ciphertext

def decrypt(public_key, private_key, ciphertext):
    p, _, _ = public_key
    B, s = ciphertext

    # Tính B^a mod p để giải mã
    plaintext = (pow(B, private_key, p) * pow(s, -1, p)) % p
    return plaintext

def hash_message(message):
    # Sử dụng hàm băm SHA-256 để tạo giá trị băm của thông điệp
    h = SHA256.new()
    h.update(str(message).encode())
    return int.from_bytes(h.digest(), byteorder='big')

def sign(private_key, message):
    p, _, A = public_key

    # Tạo chữ ký số
    k = number.getRandomRange(2, p-2)
    r = pow(A, k, p)

    # Tính giá trị băm của thông điệp
    hash_value = hash_message(message)
    # hash_value = message

    # Tính s = (hash_value - private_key * r) * (k^-1 mod (p-1))
    k_inverse = pow(k, -1, p-1)
    s = (hash_value - private_key * r) * k_inverse % (p-1)

    return (r, s)

def verify(public_key, signature, message):
    p, g, A = public_key
    r, s = signature

    # Tính giá trị băm của thông điệp
    hash_value = hash_message(message)
    # hash_value = message

    # Tính u1 = (hash_value * s^-1) mod (p-1) và u2 = (r * s^-1) mod (p-1)
    s_inverse = pow(s, -1, p-1)
    u1 = (hash_value * s_inverse) % (p-1)
    u2 = (r * s_inverse) % (p-1)

    # Tính v = (g^u1 * A^u2 mod p) mod p-1
    v = (pow(g, u1, p) * pow(A, u2, p)) % p % (p-1)

    # Chữ ký hợp lệ nếu v == r
    return v == r

# Sử dụng chương trình
bit_length = 256
public_key, private_key = generate_keypair(bit_length)
print("Khóa công khai:", public_key)
print("Khóa bí mật:", private_key)

plaintext = 42
print("Bản rõ:", plaintext)

# Mã hóa và giải mã
ciphertext = encrypt(public_key, plaintext)
print("Bản mã:", ciphertext)

decrypted_text = decrypt(public_key, private_key, ciphertext)
print("Giải mã:", decrypted_text)

# Ký số và kiểm tra chữ ký
signature = sign(private_key, plaintext)
print("Chữ ký số:", signature)

is_valid_signature = verify(public_key, signature, plaintext)
print("Chữ ký hợp lệ:", is_valid_signature)