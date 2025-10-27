from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import number

# --- THÔNG SỐ ĐƯỜNG CONG VÀ CHUẨN MÃ HÓA ---

# Chuẩn mực đường cong được sử dụng phổ biến (ví dụ: NIST P-256)
CURVE_NAME = 'P-256' 
KEY_LENGTH = 16 # Độ dài khóa AES 128 bit (16 bytes)

# --- 1. HÀM THỎA THUẬN KHÓA ECDH ---

def tao_cap_khoa():
    """Tạo khóa bí mật (private key) và khóa công khai (public key) cho ECC."""
    # Khóa ECC trong PyCryptodome chứa cả d (bí mật) và điểm công khai Q (P_A hoặc P_B)
    key = ECC.generate(curve=CURVE_NAME)
    return key

def tinh_khoa_chung_ecdh(private_key_a, public_key_b):
    """
    Tính Khóa Bí Mật Chung S.
    S = d_A * P_B (Điểm)
    Sau đó, băm tọa độ x của S thành khóa đối xứng dùng cho AES.
    """
    # Lấy số mũ bí mật d_A từ khóa riêng của Alice
    d_A = private_key_a.d
    
    # Lấy điểm công khai P_B từ khóa công khai của Bob
    P_B = public_key_b.pointQ
    
    # SỬA LỖI: Thực hiện phép nhân vô hướng S = d_A * P_B
    shared_point = d_A * P_B 
    
    # Lấy tọa độ x của điểm S và băm nó thành khóa đối xứng có độ dài cố định (SHA256)
    # Tọa độ x là số lớn, cần chuyển thành bytes trước khi băm
    x_coord = shared_point.x.to_bytes() 
    
    # Dùng hàm băm để tạo ra khóa K có độ dài cố định (Khóa đối xứng)
    shared_secret_key = SHA256.new(x_coord).digest()
    
    # Chỉ lấy 16 byte đầu (128 bit) cho khóa AES-128
    return shared_secret_key[:KEY_LENGTH]

# --- 2. HÀM MÃ HÓA VÀ GIẢI MÃ ĐỐI XỨNG (SỬ DỤNG KHÓA CHUNG) ---

# Thường dùng AES ở chế độ GCM (Galois/Counter Mode) để đảm bảo tính xác thực
def ma_hoa_aes(key, data):
    """Mã hóa dữ liệu bằng Khóa Bí Mật Chung (AES-GCM)."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    # Trả về nonce, bản mã và tag (để kiểm tra xác thực)
    return cipher.nonce, ciphertext, tag

def giai_ma_aes(key, nonce, ciphertext, tag):
    """Giải mã dữ liệu bằng Khóa Bí Mật Chung."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except ValueError:
        return "LỖI GIẢI MÃ: Kiểm tra xác thực thất bại (Có thể do khóa sai hoặc dữ liệu bị thay đổi)."

# --- CHẠY CHƯƠNG TRÌNH ---
if __name__ == '__main__':
    thong_diep_goc = "Đây là thông điệp bí mật gửi qua kênh ECDH an toàn."
    print("==============================================")
    print(f"Hệ mật Đường cong Elliptic (ECDH) - Chuẩn {CURVE_NAME}")
    print(f"Thông điệp gốc: {thong_diep_goc}")
    print("==============================================")
    
    # 1. ALICE VÀ BOB TẠO KHÓA RIÊNG
    print("\n[1. TẠO KHÓA RIÊNG]")
    
    # Alice tạo cặp khóa
    alice_private_key = tao_cap_khoa() 
    alice_public_key = alice_private_key.public_key()
    print(f"Alice Private Key (d_A): {alice_private_key.d}")
    
    # Bob tạo cặp khóa
    bob_private_key = tao_cap_khoa()
    bob_public_key = bob_private_key.public_key()
    print(f"Bob Private Key (d_B): {bob_private_key.d}")
    
    # 2. ALICE VÀ BOB TÍNH KHÓA CHUNG S
    print("\n[2. THỎA THUẬN KHÓA ECDH]")
    
    # Alice tính S_A = d_A * P_B (Sử dụng khóa riêng của mình và khóa công khai của Bob)
    shared_secret_A = tinh_khoa_chung_ecdh(alice_private_key, bob_public_key)
    print(f"Khóa chung của Alice (Hashed X-coord): {shared_secret_A.hex()}...")
    
    # Bob tính S_B = d_B * P_A (Sử dụng khóa riêng của mình và khóa công khai của Alice)
    shared_secret_B = tinh_khoa_chung_ecdh(bob_private_key, alice_public_key)
    print(f"Khóa chung của Bob (Hashed X-coord): {shared_secret_B.hex()}...")
    
    # Kiểm tra
    if shared_secret_A == shared_secret_B:
        print("=> Khóa chung thành công! Alice và Bob có cùng Khóa Bí Mật (Shared Secret). ✅")
        shared_secret_key = shared_secret_A
    else:
        print("=> LỖI: Khóa chung không khớp! ❌")
        exit()

    # 3. ALICE MÃ HÓA BẰNG KHÓA CHUNG
    print("\n[3. MÃ HÓA (ALICE gửi BOB)]")
    nonce, ciphertext, tag = ma_hoa_aes(shared_secret_key, thong_diep_goc)
    print(f"Nonce: {nonce.hex()}")
    print(f"Bản mã (Ciphertext): {ciphertext.hex()}...")
    print(f"Tag: {tag.hex()}...")
    
    # 4. BOB GIẢI MÃ BẰNG KHÓA CHUNG
    print("\n[4. GIẢI MÃ (BOB nhận từ ALICE)]")
    thong_diep_giai_ma = giai_ma_aes(shared_secret_key, nonce, ciphertext, tag)
    print(f"Thông điệp sau giải mã: {thong_diep_giai_ma}")
    
    # 5. KIỂM TRA KẾT QUẢ
    print("\n[KIỂM TRA]")
    if thong_diep_goc == thong_diep_giai_ma:
        print("Toàn bộ quá trình Thỏa thuận khóa và Mã hóa/Giải mã THÀNH CÔNG! ✅")
    else:
        print("Lỗi trong quá trình Mã hóa/Giải mã! ❌")