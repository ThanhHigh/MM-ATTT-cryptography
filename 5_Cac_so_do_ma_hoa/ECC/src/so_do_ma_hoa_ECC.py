"""
Chương trình mã hóa và giải mã sử dụng Elliptic Curve Cryptography (ECC)
Sơ đồ: ECIES (Elliptic Curve Integrated Encryption Scheme)
"""

from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
import binascii

PUBLIC_FILE = "public-key.pem"
PRIVATE_FILE = "private-key.pem"

def print_section(title):
    """In tiêu đề phần"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)

def print_step(step_num, description):
    """In bước thực hiện"""
    print(f"\n[Bước {step_num}] {description}")
    print("-" * 70)

def point_to_bytes(point):
    """Chuyển điểm ECC sang bytes (uncompressed format)"""
    x_bytes = point.x.to_bytes(32, byteorder='big')
    y_bytes = point.y.to_bytes(32, byteorder='big')
    return b'\x04' + x_bytes + y_bytes

def scalar_mult(private_key_int, public_point):
    """Nhân vô hướng điểm với scalar"""
    # Tính toán shared point: private_key * public_point
    shared_point = public_point * private_key_int
    return shared_point

def derive_keys(shared_secret):
    """Sinh khóa mã hóa và MAC từ shared secret sử dụng HKDF"""
    print("   > Sử dụng HKDF-SHA256 để sinh khóa...")
    # Sử dụng HKDF để sinh 48 bytes: 32 cho AES-256 + 16 cho MAC
    derived = HKDF(shared_secret, 48, b'', SHA256)
    enc_key = derived[:32]  # 32 bytes cho AES-256
    mac_key = derived[32:]  # 16 bytes cho HMAC
    return enc_key, mac_key

def encrypt_ecc(plaintext, public_key):
    """
    Mã hóa dữ liệu sử dụng ECIES
    
    Args:
        plaintext: Dữ liệu cần mã hóa (bytes)
        public_key: Khóa công khai ECC
    
    Returns:
        Ciphertext bao gồm: ephemeral_public_key + iv + encrypted_data + mac
    """
    print_section("QUÁ TRÌNH MÃ HÓA (ECIES)")
    
    # Bước 1: Tạo khóa tạm thời (ephemeral key pair)
    print_step(1, "Tạo cặp khóa tạm thời (Ephemeral Key Pair)")
    ephemeral_key = ECC.generate(curve='P-256')
    print(f"   > Khóa riêng tạm thời: {hex(ephemeral_key.d)[:50]}...")
    ephemeral_public_point = ephemeral_key.pointQ
    print(f"   > Khóa công khai tạm thời (x): {hex(ephemeral_public_point.x)[:50]}...")
    print(f"   > Khóa công khai tạm thời (y): {hex(ephemeral_public_point.y)[:50]}...")
    
    # Bước 2: Tính shared secret sử dụng ECDH
    print_step(2, "Tính Shared Secret (ECDH)")
    print(f"   > Thực hiện: ephemeral_private_key × recipient_public_key")
    recipient_public_point = public_key.pointQ
    shared_point = scalar_mult(ephemeral_key.d, recipient_public_point)
    print(f"   > Shared Point (x): {hex(shared_point.x)[:50]}...")
    print(f"   > Shared Point (y): {hex(shared_point.y)[:50]}...")
    
    # Chuyển shared point thành bytes
    shared_secret = shared_point.x.to_bytes(32, byteorder='big')
    print(f"   > Shared Secret: {binascii.hexlify(shared_secret[:16]).decode()}...")
    
    # Bước 3: Sinh khóa mã hóa và MAC
    print_step(3, "Sinh khóa mã hóa và khóa MAC từ Shared Secret")
    enc_key, mac_key = derive_keys(shared_secret)
    print(f"   > Khóa mã hóa (AES-256): {binascii.hexlify(enc_key[:16]).decode()}...")
    print(f"   > Khóa MAC (HMAC): {binascii.hexlify(mac_key).decode()}...")
    
    # Bước 4: Mã hóa plaintext sử dụng AES-256-GCM
    print_step(4, "Mã hóa dữ liệu sử dụng AES-256-GCM")
    print(f"   > Plaintext: {plaintext.decode() if isinstance(plaintext, bytes) else plaintext}")
    print(f"   > Độ dài plaintext: {len(plaintext)} bytes")
    
    cipher = AES.new(enc_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    print(f"   > IV (nonce): {binascii.hexlify(cipher.nonce).decode()}")
    print(f"   > Ciphertext: {binascii.hexlify(ciphertext).decode()}")
    print(f"   > Authentication Tag: {binascii.hexlify(tag).decode()}")
    
    # Bước 5: Tạo MAC cho toàn bộ ciphertext
    print_step(5, "Tạo HMAC để đảm bảo tính toàn vẹn")
    ephemeral_public_bytes = point_to_bytes(ephemeral_public_point)
    mac_data = ephemeral_public_bytes + cipher.nonce + ciphertext + tag
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(mac_data)
    mac = h.digest()
    print(f"   > HMAC: {binascii.hexlify(mac[:16]).decode()}...")
    
    # Bước 6: Kết hợp tất cả thành ciphertext cuối cùng
    print_step(6, "Kết hợp các thành phần")
    final_ciphertext = ephemeral_public_bytes + cipher.nonce + ciphertext + tag + mac
    print(f"   > Ephemeral Public Key: 65 bytes")
    print(f"   > Nonce: {len(cipher.nonce)} bytes")
    print(f"   > Ciphertext: {len(ciphertext)} bytes")
    print(f"   > Auth Tag: {len(tag)} bytes")
    print(f"   > HMAC: {len(mac)} bytes")
    print(f"   > Tổng kích thước: {len(final_ciphertext)} bytes")
    
    return final_ciphertext

def decrypt_ecc(ciphertext, private_key):
    """
    Giải mã dữ liệu sử dụng ECIES
    
    Args:
        ciphertext: Dữ liệu đã mã hóa
        private_key: Khóa riêng ECC
    
    Returns:
        Plaintext đã giải mã
    """
    print_section("QUÁ TRÌNH GIẢI MÃ (ECIES)")
    
    # Bước 1: Tách các thành phần
    print_step(1, "Tách các thành phần từ ciphertext")
    ephemeral_public_bytes = ciphertext[:65]
    nonce = ciphertext[65:65+16]
    mac = ciphertext[-32:]
    tag = ciphertext[-48:-32]
    encrypted_data = ciphertext[65+16:-48]
    
    print(f"   > Ephemeral Public Key: 65 bytes")
    print(f"   > Nonce: {len(nonce)} bytes")
    print(f"   > Encrypted data: {len(encrypted_data)} bytes")
    print(f"   > Auth Tag: {len(tag)} bytes")
    print(f"   > HMAC: {len(mac)} bytes")
    
    # Bước 2: Phục hồi ephemeral public key
    print_step(2, "Phục hồi Ephemeral Public Key")
    x = int.from_bytes(ephemeral_public_bytes[1:33], byteorder='big')
    y = int.from_bytes(ephemeral_public_bytes[33:65], byteorder='big')
    print(f"   > Ephemeral Public Key (x): {hex(x)[:50]}...")
    print(f"   > Ephemeral Public Key (y): {hex(y)[:50]}...")
    
    ephemeral_public_key = ECC.construct(curve='P-256', point_x=x, point_y=y)
    ephemeral_public_point = ephemeral_public_key.pointQ
    
    # Bước 3: Tính shared secret
    print_step(3, "Tính Shared Secret (ECDH)")
    print(f"   > Thực hiện: recipient_private_key × ephemeral_public_key")
    shared_point = scalar_mult(private_key.d, ephemeral_public_point)
    print(f"   > Shared Point (x): {hex(shared_point.x)[:50]}...")
    print(f"   > Shared Point (y): {hex(shared_point.y)[:50]}...")
    
    shared_secret = shared_point.x.to_bytes(32, byteorder='big')
    print(f"   > Shared Secret: {binascii.hexlify(shared_secret[:16]).decode()}...")
    
    # Bước 4: Sinh khóa mã hóa và MAC
    print_step(4, "Sinh khóa giải mã và khóa MAC từ Shared Secret")
    enc_key, mac_key = derive_keys(shared_secret)
    print(f"   > Khóa giải mã (AES-256): {binascii.hexlify(enc_key[:16]).decode()}...")
    print(f"   > Khóa MAC (HMAC): {binascii.hexlify(mac_key).decode()}...")
    
    # Bước 5: Xác thực HMAC
    print_step(5, "Xác thực HMAC")
    mac_data = ephemeral_public_bytes + nonce + encrypted_data + tag
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(mac_data)
    expected_mac = h.digest()
    
    if mac != expected_mac:
        print(f"   > ❌ HMAC không hợp lệ!")
        raise ValueError("Xác thực MAC thất bại - dữ liệu có thể đã bị thay đổi")
    print(f"   > ✓ HMAC hợp lệ - dữ liệu không bị thay đổi")
    
    # Bước 6: Giải mã dữ liệu
    print_step(6, "Giải mã dữ liệu sử dụng AES-256-GCM")
    cipher = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(encrypted_data, tag)
    
    print(f"   > Plaintext: {plaintext.decode() if isinstance(plaintext, bytes) else plaintext}")
    print(f"   > Độ dài plaintext: {len(plaintext)} bytes")
    
    return plaintext

if __name__ == "__main__":
    print("\n" + "█"*70)
    print("█" + " "*22 + "HỆ MÃ HÓA ECC (ECIES)" + " "*22 + "█")
    print("█"*70)
    
    # Đọc khóa
    print_section("NẠP KHÓA")
    print("\n[*] Đọc khóa riêng từ file...")
    with open(PRIVATE_FILE, "rt") as f:
        private_key = ECC.import_key(f.read())
    print(f"    ✓ Đã nạp khóa riêng từ {PRIVATE_FILE}")
    print(f"    > Khóa riêng (d): {hex(private_key.d)[:50]}...")
    
    print("\n[*] Đọc khóa công khai từ file...")
    with open(PUBLIC_FILE, "rt") as f:
        public_key = ECC.import_key(f.read())
    print(f"    ✓ Đã nạp khóa công khai từ {PUBLIC_FILE}")
    print(f"    > Khóa công khai (x): {hex(public_key.pointQ.x)[:50]}...")
    print(f"    > Khóa công khai (y): {hex(public_key.pointQ.y)[:50]}...")
    
    # Dữ liệu cần mã hóa
    plaintext = b'Mid at midnight'
    
    # Mã hóa
    ciphertext = encrypt_ecc(plaintext, public_key)
    
    # Giải mã
    decrypted = decrypt_ecc(ciphertext, private_key)
    
    # Kết quả
    print_section("KẾT QUẢ")
    print(f"\n✓ Plaintext gốc:      {plaintext.decode()}")
    print(f"✓ Plaintext giải mã:  {decrypted.decode()}")
    print(f"✓ Kết quả khớp:       {plaintext == decrypted}")
    
    # Ghi kết quả vào file
    print_section("LƯU KẾT QUẢ")
    output_file = "../ket_qua/ECC_encryption.txt"
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("="*70 + "\n")
            f.write("KẾT QUẢ MÃ HÓA VÀ GIẢI MÃ SỬ DỤNG ECC (ECIES)\n")
            f.write("="*70 + "\n\n")
            
            f.write("1. THÔNG TIN KHÓA\n")
            f.write("-" * 70 + "\n")
            f.write(f"Khóa riêng (d): {hex(private_key.d)}\n")
            f.write(f"Khóa công khai (x): {hex(public_key.pointQ.x)}\n")
            f.write(f"Khóa công khai (y): {hex(public_key.pointQ.y)}\n\n")
            
            f.write("2. DỮ LIỆU\n")
            f.write("-" * 70 + "\n")
            f.write(f"Plaintext: {plaintext.decode()}\n")
            f.write(f"Độ dài plaintext: {len(plaintext)} bytes\n\n")
            
            f.write("3. KẾT QUẢ MÃ HÓA\n")
            f.write("-" * 70 + "\n")
            f.write(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}\n")
            f.write(f"Độ dài ciphertext: {len(ciphertext)} bytes\n\n")
            
            f.write("4. KẾT QUẢ GIẢI MÃ\n")
            f.write("-" * 70 + "\n")
            f.write(f"Plaintext giải mã: {decrypted.decode()}\n")
            f.write(f"Kết quả khớp: {plaintext == decrypted}\n\n")
            
            f.write("5. SƠ ĐỒ ECIES\n")
            f.write("-" * 70 + "\n")
            f.write("Mã hóa:\n")
            f.write("  1. Tạo cặp khóa tạm thời (ephemeral key pair)\n")
            f.write("  2. Tính shared secret = ephemeral_private × recipient_public\n")
            f.write("  3. Sinh khóa AES và MAC từ shared secret (HKDF)\n")
            f.write("  4. Mã hóa plaintext bằng AES-256-GCM\n")
            f.write("  5. Tạo HMAC cho toàn bộ ciphertext\n")
            f.write("  6. Kết hợp: ephemeral_public + nonce + ciphertext + tag + mac\n\n")
            f.write("Giải mã:\n")
            f.write("  1. Tách các thành phần từ ciphertext\n")
            f.write("  2. Phục hồi ephemeral public key\n")
            f.write("  3. Tính shared secret = recipient_private × ephemeral_public\n")
            f.write("  4. Sinh khóa AES và MAC từ shared secret\n")
            f.write("  5. Xác thực HMAC\n")
            f.write("  6. Giải mã bằng AES-256-GCM\n")
        
        print(f"✓ Đã lưu kết quả vào: {output_file}")
    except Exception as e:
        print(f"❌ Lỗi khi lưu file: {e}")
    
    print("\n" + "█"*70)
    print("█" + " "*22 + "HOÀN TẤT CHƯƠNG TRÌNH" + " "*21 + "█")
    print("█"*70 + "\n")
    