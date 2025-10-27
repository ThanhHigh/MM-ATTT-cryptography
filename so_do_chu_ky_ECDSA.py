from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto import Random
from binascii import hexlify

# --- THÔNG SỐ ĐƯỜNG CONG VÀ HASH ---

# Chuẩn mực đường cong được sử dụng phổ biến
CURVE_NAME = 'P-256' 
HASH_ALGORITHM = SHA256

# --- 1. TẠO KHÓA ECDSA ---

def tao_cap_khoa_ecdsa():
    """Tạo khóa bí mật và khóa công khai cho ECDSA."""
    # Khóa ECC được tạo ra tự động chứa d (bí mật) và điểm công khai Q
    private_key = ECC.generate(curve=CURVE_NAME)
    public_key = private_key.public_key()
    return private_key, public_key

# --- 2. TẠO CHỮ KÝ (Signing) ---

def tao_chu_ky_ecdsa(private_key, thong_diep):
    """
    Tạo chữ ký số (r, s) cho thông điệp.
    Sử dụng thuật toán DSS với SHA256.
    """
    # 1. Băm thông điệp
    h = HASH_ALGORITHM.new(thong_diep.encode('utf-8'))
    
    # 2. Tạo đối tượng ký DSS
    signer = DSS.new(private_key, 'fips-186-3')
    
    # 3. Ký (tính r và s)
    # PyCryptodome tự động quản lý việc chọn số ngẫu nhiên k và tính toán r, s
    signature = signer.sign(h) 
    
    return signature

# --- 3. XÁC MINH CHỮ KÝ (Verification) ---

def xac_minh_chu_ky_ecdsa(public_key, thong_diep, signature):
    """
    Xác minh chữ ký số (r, s) của thông điệp bằng khóa công khai.
    """
    # 1. Băm thông điệp
    h = HASH_ALGORITHM.new(thong_diep.encode('utf-8'))
    
    # 2. Tạo đối tượng xác minh DSS
    verifier = DSS.new(public_key, 'fips-186-3')
    
    # 3. Xác minh chữ ký
    try:
        # Nếu xác minh thành công, không có exception nào được ném ra
        verifier.verify(h, signature)
        return True
    except ValueError:
        # Nếu xác minh thất bại (chữ ký sai hoặc thông điệp bị thay đổi)
        return False

# --- CHẠY CHƯƠNG TRÌNH ---
if __name__ == '__main__':
    thong_diep_goc = "Meed at midnight"
    
    print("==============================================")
    print(f"Sơ đồ Chữ ký Số ECDSA - Chuẩn {CURVE_NAME} với SHA256")
    print(f"Thông điệp cần ký: {thong_diep_goc}")
    print("==============================================")
    
    # 1. ALICE TẠO KHÓA
    print("\n[1. TẠO CẶP KHÓA ALICE]")
    alice_private_key, alice_public_key = tao_cap_khoa_ecdsa() 
    print(f"Alice Private Key (d_A): {alice_private_key.d}")
    print(f"Alice Public Key (P_A): ({alice_public_key.pointQ.x}, {alice_public_key.pointQ.y})")
    
    # 2. ALICE KÝ THÔNG ĐIỆP
    print("\n[2. TẠO CHỮ KÝ]")
    signature = tao_chu_ky_ecdsa(alice_private_key, thong_diep_goc)
    print(f"Chữ ký số (Signature): {hexlify(signature).decode('utf-8')}")
    
    # 3. BOB XÁC MINH CHỮ KÝ
    print("\n[3. XÁC MINH CHỮ KÝ (Với thông điệp gốc)]")
    is_valid = xac_minh_chu_ky_ecdsa(alice_public_key, thong_diep_goc, signature)
    
    print("\n[KẾT QUẢ XÁC MINH 1]")
    if is_valid:
        print("Chữ ký HỢP LỆ! Thông điệp đúng là từ Alice và không bị sửa đổi. ✅")
    else:
        print("Chữ ký KHÔNG HỢP LỆ! ❌")

    # 4. THỬ NGHIỆM TÍNH TOÀN VẸN (Thay đổi thông điệp)
    print("-" * 30)
    thong_diep_gia = "Meet at dawn"  # Thông điệp đã bị thay đổi
    print(f"Thử xác minh với thông điệp đã sửa: {thong_diep_gia}")
    
    is_valid_tampered = xac_minh_chu_ky_ecdsa(alice_public_key, thong_diep_gia, signature)
    
    print("\n[KẾT QUẢ XÁC MINH 2]")
    if not is_valid_tampered:
        print("Chữ ký KHÔNG HỢP LỆ! Phát hiện thông điệp đã bị thay đổi (Tính toàn vẹn). ✅")
    else:
        print("Lỗi! Lẽ ra chữ ký phải không hợp lệ. ❌")