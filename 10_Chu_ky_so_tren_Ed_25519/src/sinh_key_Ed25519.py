"""
Chương trình sinh khóa cho Chữ ký Số Ed25519
Tạo cặp khóa công khai và khóa bí mật
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import os
from datetime import datetime

# ==================== CẤU HÌNH ====================
PRIVATE_KEY_FILE = "private-key-ed25519.pem"
PUBLIC_KEY_FILE = "public-key-ed25519.pem"
OUTPUT_FILE = "../ket_qua/sinh_key_Ed25519.txt"

# ==================== HÀM TIỆN ÍCH ====================
def print_and_log(message, file_handle=None):
    """In ra console và ghi vào file"""
    print(message)
    if file_handle:
        file_handle.write(message + "\n")

def format_hex(data, bytes_per_line=32):
    """Format dữ liệu hex thành nhiều dòng để dễ đọc"""
    hex_str = data.hex()
    lines = []
    for i in range(0, len(hex_str), bytes_per_line * 2):
        lines.append(hex_str[i:i + bytes_per_line * 2])
    return "\n    ".join(lines)

# ==================== CHƯƠNG TRÌNH CHÍNH ====================
def main():
    # Tạo thư mục output nếu chưa có
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as output_file:
        # Header
        header = f"""
{'='*80}
                SINH KHÓA CHO CHỮ KÝ SỐ Ed25519
            Edwards-curve Digital Signature Algorithm
{'='*80}
Thời gian thực hiện: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Thuật toán: Ed25519 (EdDSA trên Curve25519)
Độ dài khóa: 256 bits
Mức bảo mật: 128 bits (tương đương RSA-3072)
{'='*80}
"""
        print_and_log(header, output_file)
        
        # ==================== BƯỚC 1: SINH KHÓA BÍ MẬT ====================
        print_and_log("\n[BƯỚC 1] SINH KHÓA BÍ MẬT (Private Key)", output_file)
        print_and_log("-" * 80, output_file)
        
        print_and_log("\n1.1. Tạo khóa bí mật Ed25519:", output_file)
        print_and_log("    - Ed25519 sử dụng đường cong Edwards: Curve25519", output_file)
        print_and_log("    - Khóa bí mật: 32 bytes (256 bits) ngẫu nhiên", output_file)
        
        private_key = Ed25519PrivateKey.generate()
        
        print_and_log("    ✓ Khóa bí mật được tạo thành công", output_file)
        
        # Lấy raw private key bytes
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        print_and_log(f"\n1.2. Khóa bí mật (raw bytes - hex):", output_file)
        print_and_log(f"    {format_hex(private_bytes)}", output_file)
        print_and_log(f"    Độ dài: {len(private_bytes)} bytes", output_file)
        
        # ==================== BƯỚC 2: SINH KHÓA CÔNG KHAI ====================
        print_and_log("\n[BƯỚC 2] SINH KHÓA CÔNG KHAI (Public Key)", output_file)
        print_and_log("-" * 80, output_file)
        
        print_and_log("\n2.1. Tạo khóa công khai từ khóa bí mật:", output_file)
        print_and_log("    - Khóa công khai = scalar * base_point", output_file)
        print_and_log("    - Base point là điểm sinh trên Curve25519", output_file)
        
        public_key = private_key.public_key()
        
        print_and_log("    ✓ Khóa công khai được tạo thành công", output_file)
        
        # Lấy raw public key bytes
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        print_and_log(f"\n2.2. Khóa công khai (raw bytes - hex):", output_file)
        print_and_log(f"    {format_hex(public_bytes)}", output_file)
        print_and_log(f"    Độ dài: {len(public_bytes)} bytes", output_file)
        
        # ==================== BƯỚC 3: LƯU KHÓA VÀO FILE PEM ====================
        print_and_log("\n[BƯỚC 3] LƯU KHÓA VÀO FILE (Định dạng PEM)", output_file)
        print_and_log("-" * 80, output_file)
        
        # Lưu khóa bí mật
        print_and_log(f"\n3.1. Lưu khóa bí mật vào file: {PRIVATE_KEY_FILE}", output_file)
        
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(pem_private)
        
        print_and_log("    ✓ Đã lưu khóa bí mật", output_file)
        print_and_log(f"    Định dạng: PEM (PKCS#8)", output_file)
        print_and_log(f"    Kích thước file: {len(pem_private)} bytes", output_file)
        
        print_and_log(f"\n    Nội dung file PEM:", output_file)
        pem_lines = pem_private.decode('utf-8').strip().split('\n')
        for line in pem_lines:
            print_and_log(f"    {line}", output_file)
        
        # Lưu khóa công khai
        print_and_log(f"\n3.2. Lưu khóa công khai vào file: {PUBLIC_KEY_FILE}", output_file)
        
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(pem_public)
        
        print_and_log("    ✓ Đã lưu khóa công khai", output_file)
        print_and_log(f"    Định dạng: PEM (SubjectPublicKeyInfo)", output_file)
        print_and_log(f"    Kích thước file: {len(pem_public)} bytes", output_file)
        
        print_and_log(f"\n    Nội dung file PEM:", output_file)
        pem_lines = pem_public.decode('utf-8').strip().split('\n')
        for line in pem_lines:
            print_and_log(f"    {line}", output_file)
        
        # ==================== BƯỚC 4: THÔNG TIN VỀ Ed25519 ====================
        print_and_log("\n[BƯỚC 4] THÔNG TIN VỀ Ed25519", output_file)
        print_and_log("-" * 80, output_file)
        
        print_and_log("\n4.1. Đặc điểm của Ed25519:", output_file)
        print_and_log("    ✓ Tốc độ ký và xác thực rất nhanh", output_file)
        print_and_log("    ✓ Khóa và chữ ký ngắn gọn (32 bytes, 64 bytes)", output_file)
        print_and_log("    ✓ Deterministic (không cần RNG cho mỗi lần ký)", output_file)
        print_and_log("    ✓ Kháng được các tấn công side-channel", output_file)
        print_and_log("    ✓ Không có patent encumbrance", output_file)
        
        print_and_log("\n4.2. So sánh với các thuật toán khác:", output_file)
        print_and_log("    Ed25519 (256 bit)  ≈  RSA-3072 bit  ≈  ECDSA P-256", output_file)
        print_and_log("    - Ed25519 nhanh hơn cả RSA và ECDSA", output_file)
        print_and_log("    - Chữ ký Ed25519: 64 bytes", output_file)
        print_and_log("    - Chữ ký RSA-3072: 384 bytes", output_file)
        print_and_log("    - Chữ ký ECDSA P-256: ~70 bytes", output_file)
        
        print_and_log("\n4.3. Thông số kỹ thuật:", output_file)
        print_and_log("    - Đường cong: Curve25519 (biến thể Edwards)", output_file)
        print_and_log("    - Prime field: 2^255 - 19", output_file)
        print_and_log("    - Base point order: 2^252 + ...", output_file)
        print_and_log("    - Hash function: SHA-512", output_file)
        print_and_log("    - Signature scheme: EdDSA", output_file)
        
        print_and_log("\n4.4. Ứng dụng thực tế:", output_file)
        print_and_log("    - OpenSSH (ssh-ed25519)", output_file)
        print_and_log("    - GnuPG và OpenPGP", output_file)
        print_and_log("    - Signal Protocol", output_file)
        print_and_log("    - TLS 1.3", output_file)
        print_and_log("    - Monero, Cardano, Stellar (cryptocurrencies)", output_file)
        print_and_log("    - DNSSEC", output_file)
        
        print_and_log("\n4.5. Lưu ý bảo mật:", output_file)
        print_and_log("    ⚠ Bảo vệ khóa bí mật cẩn thận", output_file)
        print_and_log("    ⚠ Không chia sẻ file private-key-ed25519.pem", output_file)
        print_and_log("    ⚠ Khóa công khai có thể chia sẻ công khai", output_file)
        print_and_log("    ⚠ Nên sử dụng mật khẩu mã hóa cho private key trong production", output_file)
        
        # ==================== TỔNG KẾT ====================
        summary = f"""
{'='*80}
                            TỔNG KẾT
{'='*80}
Thuật toán:             Ed25519 (EdDSA)
Độ dài khóa bí mật:     32 bytes (256 bits)
Độ dài khóa công khai:  32 bytes (256 bits)
Định dạng lưu:          PEM (PKCS#8 và SubjectPublicKeyInfo)

File được tạo:
  ✓ {PRIVATE_KEY_FILE} - Khóa bí mật (BẢO MẬT)
  ✓ {PUBLIC_KEY_FILE} - Khóa công khai (Có thể công khai)

✓ Sinh khóa thành công!
✓ Kết quả đã được lưu vào: {OUTPUT_FILE}
✓ Sẵn sàng sử dụng cho chữ ký số Ed25519
{'='*80}
"""
        print_and_log(summary, output_file)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n✗ Chương trình bị hủy bởi người dùng.")
    except Exception as e:
        print(f"\n\n✗ LỖI: {e}")
        import traceback
        traceback.print_exc()
