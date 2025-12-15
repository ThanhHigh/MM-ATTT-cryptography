from Crypto.Util.number import getPrime, isPrime, getRandomRange, long_to_bytes
from Crypto.Hash import SHA256
import sys

# GitHub Copilot
# File: DH_int_output.py
# Yêu cầu: pycryptodome (pip install pycryptodome)
# Chương trình minh họa Diffie-Hellman, in tất cả các giá trị dưới dạng integer (decimal).

def gen_safe_prime(q_bits=256, max_tries=1000):
    """Sinh p = 2*q + 1 với q prime (safe prime). q_bits: kích thước q (bit)."""
    for _ in range(max_tries):
        q = getPrime(q_bits)
        p = 2 * q + 1
        if isPrime(p):
            return p, q
    raise ValueError("Không tìm được safe prime trong giới hạn thử nghiệm. Tăng q_bits hoặc max_tries.")

def derive_128bit_key_int(shared_int):
    """Chuyển shared integer thành bytes, băm SHA-256, trả về 128-bit key dưới dạng int."""
    s_bytes = long_to_bytes(shared_int)
    h = SHA256.new(s_bytes).digest()
    key16 = h[:16]  # 16 bytes = 128 bits
    return int.from_bytes(key16, byteorder='big')

def main():
    q_bits = 256
    print(f"Generating safe prime with q ~ {q_bits} bits (this may take a while)...")
    p, q = gen_safe_prime(q_bits)
    alpha = 2

    if pow(alpha, q, p) != 1:
        for cand in range(2, 200):
            if pow(cand, q, p) == 1:
                alpha = cand
                break

    a = getRandomRange(2, q - 1)
    b = getRandomRange(2, q - 1)

    A = pow(alpha, a, p)
    B = pow(alpha, b, p)

    K_A_int = pow(B, a, p)
    K_B_int = pow(A, b, p)
    if K_A_int != K_B_int:
        print("Lỗi: khóa chung K_A và K_B không khớp!", file=sys.stderr)
        sys.exit(1)

    key128_a_int = derive_128bit_key_int(K_A_int)
    key128_b_int = derive_128bit_key_int(K_B_int)

    print("\n--- Diffie-Hellman parameters and values (all as integers) ---")
    print(f"p (decimal)             : {p}")
    print(f"q (decimal)             : {q}")
    print(f"alpha (g)               : {alpha}")
    print("")
    print("Alice:")
    print(f"  a (private, decimal)   : {a}")
    print(f"  A = g^a mod p (decimal): {A}")
    print("")
    print("Bob:")
    print(f"  b (private, decimal)   : {b}")
    print(f"  B = g^b mod p (decimal): {B}")
    print("")
    print("Shared secret (raw int):")
    print(f"  K_int (decimal)        : {K_A_int}")
    print("")
    print("Derived 128-bit keys (as integers):")
    print(f"  K_A (Alice)            : {key128_a_int}  (128 bits)")
    print(f"  K_B (Bob)              : {key128_b_int}  (128 bits)")
    print("")
    print("Kiểm tra: K_A == K_B ->", key128_a_int == key128_b_int)

if __name__ == "__main__":
    main()
