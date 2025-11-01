from Crypto.Util.number import bytes_to_long, long_to_bytes
import random
from pathlib import Path

# Import loader from doc_key_ElGamal (expects the PEM-like files in the same folder)
from doc_key_ElGamal import load_elgamal_keypair


def elgamal_encrypt(pubkey, m: int, k: int | None = None):
    """Encrypt integer m with public key object pubkey.

    Returns (c1, c2) where c1 = g^k mod p and c2 = m * y^k mod p.
    """
    # Convert key components to plain Python ints to avoid mixed-type math
    p = int(pubkey.p)
    g = int(pubkey.g)
    y = int(pubkey.y)
    if k is None:
        k = random.randrange(1, p - 1)
    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (int(m) * int(s)) % p
    return c1, c2


def elgamal_decrypt(privkey, c1: int, c2: int):
    """Decrypt ciphertext (c1, c2) using private key object privkey.

    Returns integer plaintext m.
    """
    p = int(privkey.p)
    x = int(privkey.x)
    c1 = int(c1)
    c2 = int(c2)
    s = pow(c1, x, p)
    # modular inverse of s modulo p
    try:
        s_inv = pow(s, -1, p)
    except TypeError:
        # older Python versions: use Fermat's little theorem (p is prime)
        s_inv = pow(s, p - 2, p)
    m = (c2 * s_inv) % p
    return m


def main():
    base_dir = Path(__file__).parent
    try:
        private_key, public_key = load_elgamal_keypair(base_dir)
    except Exception as e:
        print("Không thể tải khóa ElGamal từ file PEM:", e)
        return

    if public_key is None:
        print("Không tìm thấy public key. Hãy đảm bảo public-key.pem tồn tại trong thư mục.")
        return

    if private_key is None:
        print("Chỉ có public key (private key không có). Chỉ có thể mã hoá, không thể giải mã.)")

    message_bytes = b"Meet at midnight"
    message_int = bytes_to_long(message_bytes)

    if message_int >= public_key.p:
        print("Thông điệp quá lớn để mã hóa trực tiếp bằng ElGamal với độ dài khóa này.")
        return

    try:
        c1, c2 = elgamal_encrypt(public_key, message_int)

        print("--- Mã hóa ---")
        print(f"Khóa Công khai (p, g, y): ({public_key.p}, {public_key.g}, {public_key.y})")
        print(f"Thông điệp gốc (int): {message_int}")
        print(f"Bản mã c1 (int): {c1}")
        print(f"Bản mã c2 (int): {c2}")
        print(f"Bản mã (c1, c2) đã được gửi đi.")

    except Exception as e:
        print(f"Lỗi khi mã hóa: {e}")
        return

    if private_key is None:
        print("Không có private key để giải mã. Kết thúc.")
        return

    try:
        decrypted_int = elgamal_decrypt(private_key, c1, c2)
        # Chuyển số nguyên giải mã trở lại dạng bytes
        decrypted_bytes = long_to_bytes(decrypted_int)

        print("\n--- Giải mã ---")
        print(f"Thông điệp đã giải mã (int): {decrypted_int}")
        print(f"Thông điệp đã giải mã (bytes): {decrypted_bytes}")
        print(f"Thông điệp gốc và thông điệp đã giải mã khớp: {message_bytes == decrypted_bytes}")

    except Exception as e:
        print(f"Lỗi khi giải mã: {e}")


if __name__ == "__main__":
    main()