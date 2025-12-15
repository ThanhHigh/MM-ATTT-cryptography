"""
Chương trình triển khai Sơ đồ Chữ ký Số (Digital Signature) trên Hệ mật ECC
Sử dụng ECDSA (Elliptic Curve Digital Signature Algorithm) với đường cong P-256
"""

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import os
from datetime import datetime

# ==================== CẤU HÌNH ====================
PRIVATE_KEY_FILE = "private-key.pem"
PUBLIC_KEY_FILE = "public-key.pem"
OUTPUT_FILE = "../ket_qua/so_do_chu_ky_ECDSA.txt"

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
    # Tạo hoặc mở file output
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as output_file:
        # Header
        header = f"""
{'='*80}
        SƠ ĐỒ CHỮ KÝ SỐ TRÊN HỆ MẬT ECC (ECDSA)
        Elliptic Curve Digital Signature Algorithm
{'='*80}
Thời gian thực hiện: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Đường cong: P-256 (secp256r1)
Thuật toán hash: SHA-256
Thuật toán ký: ECDSA với chế độ 'fips-186-3'
{'='*80}
"""
        print_and_log(header, output_file)
        
        # ==================== BƯỚC 1: ĐỌC KHÓA ====================
        print_and_log("\n[BƯỚC 1] ĐỌC KHÓA CÔNG KHAI VÀ KHÓA BÍ MẬT", output_file)
        print_and_log("-" * 80, output_file)
        
        try:
            # Đọc khóa bí mật
            print_and_log(f"\n1.1. Đọc khóa bí mật từ file: {PRIVATE_KEY_FILE}", output_file)
            with open(PRIVATE_KEY_FILE, "r") as f:
                private_key = ECC.import_key(f.read())
            
            print_and_log(f"    ✓ Đọc thành công khóa bí mật", output_file)
            print_and_log(f"    - Đường cong: {private_key.curve}", output_file)
            print_and_log(f"    - Khóa bí mật d (hex):", output_file)
            print_and_log(f"      {format_hex(private_key.d.to_bytes(32, 'big'))}", output_file)
            
            # Đọc khóa công khai
            print_and_log(f"\n1.2. Đọc khóa công khai từ file: {PUBLIC_KEY_FILE}", output_file)
            with open(PUBLIC_KEY_FILE, "r") as f:
                public_key = ECC.import_key(f.read())
            
            print_and_log(f"    ✓ Đọc thành công khóa công khai", output_file)
            print_and_log(f"    - Điểm công khai Q(x, y):", output_file)
            print_and_log(f"      Qx = {hex(public_key.pointQ.x)}", output_file)
            print_and_log(f"      Qy = {hex(public_key.pointQ.y)}", output_file)
            
        except FileNotFoundError as e:
            error_msg = f"\n✗ LỖI: Không tìm thấy file khóa: {e}"
            print_and_log(error_msg, output_file)
            print_and_log("\nGợi ý: Chạy file sinh_key_ECC.py để tạo khóa trước.", output_file)
            return
        except Exception as e:
            error_msg = f"\n✗ LỖI khi đọc khóa: {e}"
            print_and_log(error_msg, output_file)
            return
        
        # ==================== BƯỚC 2: CHUẨN BỊ THÔNG ĐIỆP ====================
        print_and_log("\n[BƯỚC 2] CHUẨN BỊ THÔNG ĐIỆP CẦN KÝ", output_file)
        print_and_log("-" * 80, output_file)
        
        message = input("\nNhập thông điệp cần ký (hoặc Enter để dùng thông điệp mẫu): ").strip()
        if not message:
            message = "Đây là thông điệp thử nghiệm cho sơ đồ chữ ký số ECC - ECDSA với đường cong P-256"
        
        print_and_log(f"\n2.1. Thông điệp gốc:", output_file)
        print_and_log(f'    "{message}"', output_file)
        print_and_log(f"    - Độ dài: {len(message)} ký tự", output_file)
        print_and_log(f"    - Độ dài (bytes): {len(message.encode('utf-8'))} bytes", output_file)
        
        message_bytes = message.encode('utf-8')
        print_and_log(f"\n2.2. Thông điệp dạng hex:", output_file)
        print_and_log(f"    {format_hex(message_bytes)}", output_file)
        
        # ==================== BƯỚC 3: HASH THÔNG ĐIỆP ====================
        print_and_log("\n[BƯỚC 3] HASH THÔNG ĐIỆP (SHA-256)", output_file)
        print_and_log("-" * 80, output_file)
        
        hash_obj = SHA256.new(message_bytes)
        message_hash = hash_obj.digest()
        
        print_and_log(f"\n3.1. Tính hash SHA-256 của thông điệp:", output_file)
        print_and_log(f"    Hash (hex): {message_hash.hex()}", output_file)
        print_and_log(f"    Độ dài hash: {len(message_hash)} bytes (256 bits)", output_file)
        
        # ==================== BƯỚC 4: TẠO CHỮ KÝ ====================
        print_and_log("\n[BƯỚC 4] TẠO CHỮ KÝ SỐ (SIGNING)", output_file)
        print_and_log("-" * 80, output_file)
        
        print_and_log("\n4.1. Khởi tạo DSS signer với chế độ 'fips-186-3':", output_file)
        print_and_log("    - Sử dụng khóa bí mật để ký", output_file)
        print_and_log("    - Chế độ: FIPS 186-3 (deterministic nonce)", output_file)
        
        signer = DSS.new(private_key, 'fips-186-3')
        
        print_and_log("\n4.2. Thực hiện ký thông điệp:", output_file)
        print_and_log("    Thuật toán ECDSA thực hiện các bước:", output_file)
        print_and_log("    a) Sinh số ngẫu nhiên k (nonce)", output_file)
        print_and_log("    b) Tính điểm R = k * G trên đường cong", output_file)
        print_and_log("    c) Tính r = Rx mod n", output_file)
        print_and_log("    d) Tính s = k^(-1) * (hash + d*r) mod n", output_file)
        print_and_log("    e) Chữ ký = (r, s)", output_file)
        
        signature = signer.sign(hash_obj)
        
        print_and_log(f"\n4.3. Chữ ký được tạo thành công:", output_file)
        print_and_log(f"    Chữ ký (hex):", output_file)
        print_and_log(f"    {format_hex(signature)}", output_file)
        print_and_log(f"    Độ dài chữ ký: {len(signature)} bytes", output_file)
        
        # Phân tích chữ ký (r, s)
        print_and_log(f"\n4.4. Phân tích chữ ký (DER encoding):", output_file)
        print_and_log(f"    Chữ ký ECDSA gồm 2 giá trị (r, s)", output_file)
        print_and_log(f"    Được mã hóa theo chuẩn DER (Distinguished Encoding Rules)", output_file)
        
        # ==================== BƯỚC 5: XÁC THỰC CHỮ KÝ ====================
        print_and_log("\n[BƯỚC 5] XÁC THỰC CHỮ KÝ (VERIFICATION)", output_file)
        print_and_log("-" * 80, output_file)
        
        print_and_log("\n5.1. Khởi tạo DSS verifier với khóa công khai:", output_file)
        print_and_log("    - Sử dụng khóa công khai để xác thực", output_file)
        print_and_log("    - Chế độ: FIPS 186-3", output_file)
        
        verifier = DSS.new(public_key, 'fips-186-3')
        
        print_and_log("\n5.2. Thực hiện xác thực chữ ký:", output_file)
        print_and_log("    Thuật toán ECDSA xác thực các bước:", output_file)
        print_and_log("    a) Kiểm tra r, s có hợp lệ (0 < r, s < n)", output_file)
        print_and_log("    b) Tính w = s^(-1) mod n", output_file)
        print_and_log("    c) Tính u1 = hash * w mod n", output_file)
        print_and_log("    d) Tính u2 = r * w mod n", output_file)
        print_and_log("    e) Tính điểm P = u1*G + u2*Q", output_file)
        print_and_log("    f) Kiểm tra r == Px mod n", output_file)
        
        try:
            verifier.verify(hash_obj, signature)
            print_and_log("\n    ✓ XÁC THỰC THÀNH CÔNG!", output_file)
            print_and_log("    Chữ ký hợp lệ - Thông điệp chưa bị sửa đổi", output_file)
            verification_status = "HỢP LỆ"
        except ValueError:
            print_and_log("\n    ✗ XÁC THỰC THẤT BẠI!", output_file)
            print_and_log("    Chữ ký không hợp lệ hoặc thông điệp đã bị sửa đổi", output_file)
            verification_status = "KHÔNG HỢP LỆ"
        
        # ==================== BƯỚC 6: KIỂM TRA VỚI THÔNG ĐIỆP SAI ====================
        print_and_log("\n[BƯỚC 6] KIỂM TRA VỚI THÔNG ĐIỆP BỊ SỬA ĐỔI", output_file)
        print_and_log("-" * 80, output_file)
        
        tampered_message = message + " [MODIFIED]"
        print_and_log(f"\n6.1. Thông điệp bị sửa đổi:", output_file)
        print_and_log(f'    "{tampered_message}"', output_file)
        
        tampered_hash = SHA256.new(tampered_message.encode('utf-8'))
        print_and_log(f"\n6.2. Hash của thông điệp sửa đổi:", output_file)
        print_and_log(f"    {tampered_hash.digest().hex()}", output_file)
        
        print_and_log("\n6.3. Xác thực chữ ký với thông điệp sửa đổi:", output_file)
        try:
            verifier.verify(tampered_hash, signature)
            print_and_log("    ✗ BẤT THƯỜNG: Xác thực thành công (không nên xảy ra!)", output_file)
        except ValueError:
            print_and_log("    ✓ ĐÚNG: Xác thực thất bại (như mong đợi)", output_file)
            print_and_log("    Chữ ký phát hiện được thông điệp đã bị sửa đổi", output_file)
        
        # ==================== BƯỚC 7: THÔNG TIN BẢO MẬT ====================
        print_and_log("\n[BƯỚC 7] THÔNG TIN VỀ BẢO MẬT", output_file)
        print_and_log("-" * 80, output_file)
        
        print_and_log("\n7.1. Độ an toàn của hệ mật ECC P-256:", output_file)
        print_and_log("    - Độ dài khóa: 256 bits", output_file)
        print_and_log("    - Tương đương RSA: ~3072 bits", output_file)
        print_and_log("    - Mức bảo mật: 128 bits (rất cao)", output_file)
        
        print_and_log("\n7.2. Ưu điểm của ECDSA:", output_file)
        print_and_log("    ✓ Khóa ngắn hơn RSA nhưng cùng mức bảo mật", output_file)
        print_and_log("    ✓ Tốc độ ký và xác thực nhanh", output_file)
        print_and_log("    ✓ Tiết kiệm băng thông và bộ nhớ", output_file)
        print_and_log("    ✓ Phù hợp cho thiết bị di động và IoT", output_file)
        
        print_and_log("\n7.3. Ứng dụng thực tế:", output_file)
        print_and_log("    - Bitcoin và Cryptocurrency (ECDSA secp256k1)", output_file)
        print_and_log("    - TLS/SSL certificates", output_file)
        print_and_log("    - Apple iMessage", output_file)
        print_and_log("    - SSH keys", output_file)
        print_and_log("    - Digital certificates", output_file)
        
        # ==================== TỔNG KẾT ====================
        summary = f"""
{'='*80}
                            TỔNG KẾT KẾT QUẢ
{'='*80}
Thông điệp gốc:         {len(message)} ký tự
Hash SHA-256:           {message_hash.hex()}
Độ dài chữ ký:          {len(signature)} bytes
Trạng thái xác thực:    {verification_status}
Đường cong ECC:         P-256 (secp256r1)
Mức bảo mật:            128 bits

✓ Chương trình hoàn thành thành công!
✓ Kết quả đã được lưu vào: {OUTPUT_FILE}
{'='*80}
"""
        print_and_log(summary, output_file)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n✗ Chương trình bị hủy bởi người dùng.")
    except Exception as e:
        print(f"\n\n✗ LỖI NGHIÊM TRỌNG: {e}")
        import traceback
        traceback.print_exc()
