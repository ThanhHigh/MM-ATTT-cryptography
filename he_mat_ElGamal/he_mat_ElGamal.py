from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes
import random

KEY_LENGTH = 256

key = ElGamal.generate(KEY_LENGTH, get_random_bytes)

public_key = key.publickey()
private_key = key

message_bytes = b"Meet at midnight"

message_int = bytes_to_long(message_bytes)

if message_int >= key.p:
    print("Thông điệp quá lớn để mã hóa trực tiếp bằng ElGamal với độ dài khóa này.")

try:
    K_random = random.randrange(1, key.p - 1)
    c1, c2 = public_key.encrypt(message_int, K_random)

    print("--- Mã hóa ---")
    print(f"Khóa Công khai (p, g, y): ({public_key.p}, {public_key.g}, {public_key.y})")
    print(f"Thông điệp gốc (int): {message_int}")
    print(f"Bản mã c1 (int): {c1}")
    print(f"Bản mã c2 (int): {c2}")
    print(f"Bản mã (c1, c2) đã được gửi đi.")
    
except ValueError as e:
    print(f"Lỗi khi mã hóa: {e}")

try:
    decrypted_int = private_key.decrypt(c1, c2)
    
    # Chuyển số nguyên giải mã trở lại dạng bytes
    decrypted_bytes = long_to_bytes(decrypted_int)
    
    print("\n--- Giải mã ---")
    print(f"Thông điệp đã giải mã (int): {decrypted_int}")
    print(f"Thông điệp đã giải mã (bytes): {decrypted_bytes}")
    print(f"Thông điệp gốc và thông điệp đã giải mã khớp: {message_bytes == decrypted_bytes}")

except ValueError as e:
    print(f"Lỗi khi giải mã: {e}")