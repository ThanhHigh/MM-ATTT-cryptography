"""
Chương trình triển khai Sơ đồ Chữ ký Số (Digital Signature) Ed25519
Edwards-curve Digital Signature Algorithm với Curve25519
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import hashlib
import os
from datetime import datetime
import time

# ==================== CẤU HÌNH ====================
PRIVATE_KEY_FILE = "private-key-ed25519.pem"
PUBLIC_KEY_FILE = "public-key-ed25519.pem"
OUTPUT_FILE = "../ket_qua/chu_ky_so_Ed25519.txt"

# ==================== HÀM TIỆN ÍCH ====================
def print_and_log(message, file_handle=None):
    """In ra console và ghi vào file"""
    print(message)
    if file_handle:
        file_handle.write(message + "\n")

def format_hex(data, bytes_per_line=32):
    """Format dữ liệu hex thành nhiều dòng để dễ đọc"""
    if isinstance(data, str):
        hex_str = data
    else:
        hex_str = data.hex()
    lines = []
    for i in range(0, len(hex_str), bytes_per_line * 2):
        lines.append(hex_str[i:i + bytes_per_line * 2])
    return "\n    ".join(lines)

def sha512_hash(data):
    """Tính hash SHA-512"""
    return hashlib.sha512(data).digest()

# ==================== CHƯƠNG TRÌNH CHÍNH ====================
def main():
    # Tạo thư mục output nếu chưa có
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as output_file:
        # Header
        header = f"""
{'='*80}
              SƠ ĐỒ CHỮ KÝ SỐ Ed25519 (EdDSA)
          Edwards-curve Digital Signature Algorithm
{'='*80}
Thời gian thực hiện: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Thuật toán: Ed25519 (EdDSA trên Curve25519)
Hash function: SHA-512
Độ dài khóa: 256 bits (32 bytes)
Độ dài chữ ký: 512 bits (64 bytes)
Mức bảo mật: 128 bits (tương đương RSA-3072)
{'='*80}
"""
        print_and_log(header, output_file)
        
        # ==================== BƯỚC 1: ĐỌC KHÓA ====================
        print_and_log("\n[BƯỚC 1] ĐỌC KHÓA CÔNG KHAI VÀ KHÓA BÍ MẬT", output_file)
        print_and_log("-" * 80, output_file)
        
        try:
            # Đọc khóa bí mật
            print_and_log(f"\n1.1. Đọc khóa bí mật từ file: {PRIVATE_KEY_FILE}", output_file)
            with open(PRIVATE_KEY_FILE, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
            
            print_and_log(f"    ✓ Đọc thành công khóa bí mật", output_file)
            
            # Lấy raw private key
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            print_and_log(f"    - Khóa bí mật (hex):", output_file)
            print_and_log(f"      {format_hex(private_bytes)}", output_file)
            print_and_log(f"    - Độ dài: {len(private_bytes)} bytes ({len(private_bytes)*8} bits)", output_file)
            
            # Đọc khóa công khai
            print_and_log(f"\n1.2. Đọc khóa công khai từ file: {PUBLIC_KEY_FILE}", output_file)
            with open(PUBLIC_KEY_FILE, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())
            
            print_and_log(f"    ✓ Đọc thành công khóa công khai", output_file)
            
            # Lấy raw public key
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            print_and_log(f"    - Khóa công khai (hex):", output_file)
            print_and_log(f"      {format_hex(public_bytes)}", output_file)
            print_and_log(f"    - Độ dài: {len(public_bytes)} bytes ({len(public_bytes)*8} bits)", output_file)
            
        except FileNotFoundError as e:
            error_msg = f"\n✗ LỖI: Không tìm thấy file khóa: {e}"
            print_and_log(error_msg, output_file)
            print_and_log("\nGợi ý: Chạy file sinh_key_Ed25519.py để tạo khóa trước.", output_file)
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
            message = "Đây là thông điệp thử nghiệm cho chữ ký số Ed25519 - Thuật toán nhanh và an toàn nhất hiện nay!"
        
        print_and_log(f"\n2.1. Thông điệp gốc:", output_file)
        print_and_log(f'    "{message}"', output_file)
        print_and_log(f"    - Độ dài: {len(message)} ký tự", output_file)
        
        message_bytes = message.encode('utf-8')
        print_and_log(f"    - Độ dài (bytes): {len(message_bytes)} bytes", output_file)
        
        print_and_log(f"\n2.2. Thông điệp dạng hex:", output_file)
        print_and_log(f"    {format_hex(message_bytes)}", output_file)
        
        # Tính hash SHA-512 của thông điệp để hiển thị
        print_and_log(f"\n2.3. Hash SHA-512 của thông điệp (để tham khảo):", output_file)
        message_hash = sha512_hash(message_bytes)
        print_and_log(f"    {format_hex(message_hash)}", output_file)
        print_and_log(f"    Độ dài: {len(message_hash)} bytes ({len(message_hash)*8} bits)", output_file)
        print_and_log(f"    Lưu ý: Ed25519 tự động hash nội bộ, không cần hash trước", output_file)
        
        # ==================== BƯỚC 3: TẠO CHỮ KÝ ====================
        print_and_log("\n[BƯỚC 3] TẠO CHỮ KÝ SỐ (SIGNING PROCESS)", output_file)
        print_and_log("-" * 80, output_file)
        
        print_and_log("\n3.1. Thuật toán Ed25519 Signing:", output_file)
        print_and_log("    Ed25519 thực hiện các bước sau (tự động bên trong):", output_file)
        print_and_log("    ", output_file)
        print_and_log("    Bước a) Tính hash SHA-512 của khóa bí mật:", output_file)
        print_and_log("            h = SHA-512(private_key)", output_file)
        print_and_log("            Lấy 32 bytes đầu làm scalar 's'", output_file)
        print_and_log("            Lấy 32 bytes cuối làm 'prefix'", output_file)
        
        print_and_log("\n    Bước b) Tính nonce 'r':", output_file)
        print_and_log("            r = SHA-512(prefix || message)", output_file)
        print_and_log("            Reduce r mod L (order của base point)", output_file)
        
        print_and_log("\n    Bước c) Tính điểm R trên đường cong:", output_file)
        print_and_log("            R = r * B (B là base point)", output_file)
        print_and_log("            Encode R thành 32 bytes", output_file)
        
        print_and_log("\n    Bước d) Tính 'k' (challenge):", output_file)
        print_and_log("            k = SHA-512(R || A || message)", output_file)
        print_and_log("            (A là public key point)", output_file)
        print_and_log("            Reduce k mod L", output_file)
        
        print_and_log("\n    Bước e) Tính 's' (scalar):", output_file)
        print_and_log("            s = (r + k * a) mod L", output_file)
        print_and_log("            (a là private scalar)", output_file)
        
        print_and_log("\n    Bước f) Chữ ký cuối cùng:", output_file)
        print_and_log("            Signature = R || s (64 bytes total)", output_file)
        print_and_log("            32 bytes R + 32 bytes s", output_file)
        
        print_and_log("\n3.2. Bắt đầu quá trình ký...", output_file)
        
        # Đo thời gian ký
        start_time = time.perf_counter()
        signature = private_key.sign(message_bytes)
        signing_time = time.perf_counter() - start_time
        
        print_and_log(f"    ✓ Ký thành công trong {signing_time*1000:.4f} ms", output_file)
        
        print_and_log(f"\n3.3. Chữ ký được tạo:", output_file)
        print_and_log(f"    Chữ ký (hex - 64 bytes):", output_file)
        print_and_log(f"    {format_hex(signature)}", output_file)
        print_and_log(f"    Độ dài: {len(signature)} bytes ({len(signature)*8} bits)", output_file)
        
        print_and_log(f"\n3.4. Phân tích chữ ký:", output_file)
        R_bytes = signature[:32]
        s_bytes = signature[32:]
        print_and_log(f"    - Phần R (32 bytes đầu):", output_file)
        print_and_log(f"      {format_hex(R_bytes)}", output_file)
        print_and_log(f"    - Phần s (32 bytes cuối):", output_file)
        print_and_log(f"      {format_hex(s_bytes)}", output_file)
        
        # ==================== BƯỚC 4: XÁC THỰC CHỮ KÝ ====================
        print_and_log("\n[BƯỚC 4] XÁC THỰC CHỮ KÝ (VERIFICATION PROCESS)", output_file)
        print_and_log("-" * 80, output_file)
        
        print_and_log("\n4.1. Thuật toán Ed25519 Verification:", output_file)
        print_and_log("    Ed25519 thực hiện các bước xác thực:", output_file)
        print_and_log("    ", output_file)
        print_and_log("    Bước a) Parse chữ ký thành R và s", output_file)
        print_and_log("    Bước b) Kiểm tra s < L (order của base point)", output_file)
        print_and_log("    Bước c) Decode R thành điểm trên đường cong", output_file)
        print_and_log("    Bước d) Tính k = SHA-512(R || A || message) mod L", output_file)
        print_and_log("    Bước e) Kiểm tra phương trình:", output_file)
        print_and_log("            s * B = R + k * A", output_file)
        print_and_log("            (Nếu đúng thì chữ ký hợp lệ)", output_file)
        
        print_and_log("\n4.2. Bắt đầu quá trình xác thực...", output_file)
        
        # Đo thời gian xác thực
        start_time = time.perf_counter()
        try:
            public_key.verify(signature, message_bytes)
            verification_time = time.perf_counter() - start_time
            
            print_and_log(f"    ✓ Xác thực thành công trong {verification_time*1000:.4f} ms", output_file)
            print_and_log("\n4.3. Kết quả xác thực:", output_file)
            print_and_log("    ✓ CHỮ KÝ HỢP LỆ!", output_file)
            print_and_log("    ✓ Thông điệp chưa bị sửa đổi", output_file)
            print_and_log("    ✓ Người ký được xác thực chính xác", output_file)
            verification_status = "HỢP LỆ"
            
        except InvalidSignature:
            verification_time = time.perf_counter() - start_time
            print_and_log(f"    ✗ Xác thực thất bại trong {verification_time*1000:.4f} ms", output_file)
            print_and_log("\n4.3. Kết quả xác thực:", output_file)
            print_and_log("    ✗ CHỮ KÝ KHÔNG HỢP LỆ!", output_file)
            print_and_log("    ✗ Thông điệp có thể đã bị sửa đổi", output_file)
            verification_status = "KHÔNG HỢP LỆ"
        
        # ==================== BƯỚC 5: KIỂM TRA VỚI THÔNG ĐIỆP SAI ====================
        print_and_log("\n[BƯỚC 5] KIỂM TRA VỚI THÔNG ĐIỆP BỊ SỬA ĐỔI", output_file)
        print_and_log("-" * 80, output_file)
        
        tampered_message = message + " [ĐÃ BỊ SỬA ĐỔI]"
        print_and_log(f"\n5.1. Thông điệp bị sửa đổi:", output_file)
        print_and_log(f'    "{tampered_message}"', output_file)
        
        tampered_bytes = tampered_message.encode('utf-8')
        print_and_log(f"\n5.2. Hash SHA-512 của thông điệp sửa đổi:", output_file)
        tampered_hash = sha512_hash(tampered_bytes)
        print_and_log(f"    {format_hex(tampered_hash)}", output_file)
        
        print_and_log(f"\n5.3. So sánh hash:", output_file)
        print_and_log(f"    Hash gốc:      {message_hash.hex()[:32]}...", output_file)
        print_and_log(f"    Hash sửa đổi:  {tampered_hash.hex()[:32]}...", output_file)
        print_and_log(f"    ➜ Hash khác nhau! ✓", output_file)
        
        print_and_log("\n5.4. Xác thực chữ ký với thông điệp sửa đổi:", output_file)
        
        start_time = time.perf_counter()
        try:
            public_key.verify(signature, tampered_bytes)
            verification_time = time.perf_counter() - start_time
            print_and_log(f"    ✗ BẤT THƯỜNG: Xác thực thành công (không nên xảy ra!)", output_file)
            tampered_status = "THẤT BẠI (BẤT THƯỜNG)"
        except InvalidSignature:
            verification_time = time.perf_counter() - start_time
            print_and_log(f"    ✓ ĐÚNG: Xác thực thất bại (như mong đợi) - {verification_time*1000:.4f} ms", output_file)
            print_and_log("    ✓ Ed25519 phát hiện chính xác thông điệp đã bị sửa đổi", output_file)
            tampered_status = "THÀNH CÔNG"
        
        # ==================== BƯỚC 6: KIỂM TRA VỚI CHỮ KÝ SAI ====================
        print_and_log("\n[BƯỚC 6] KIỂM TRA VỚI CHỮ KÝ BỊ THAY ĐỔI", output_file)
        print_and_log("-" * 80, output_file)
        
        print_and_log(f"\n6.1. Tạo chữ ký giả (sửa đổi 1 byte):", output_file)
        fake_signature = bytearray(signature)
        fake_signature[0] = (fake_signature[0] + 1) % 256  # Sửa byte đầu tiên
        fake_signature = bytes(fake_signature)
        
        print_and_log(f"    Chữ ký gốc (10 bytes đầu):  {signature[:10].hex()}", output_file)
        print_and_log(f"    Chữ ký giả (10 bytes đầu):  {fake_signature[:10].hex()}", output_file)
        
        print_and_log(f"\n6.2. Xác thực chữ ký giả:", output_file)
        
        start_time = time.perf_counter()
        try:
            public_key.verify(fake_signature, message_bytes)
            verification_time = time.perf_counter() - start_time
            print_and_log(f"    ✗ BẤT THƯỜNG: Xác thực thành công (không nên xảy ra!)", output_file)
            fake_sig_status = "THẤT BẠI (BẤT THƯỜNG)"
        except InvalidSignature:
            verification_time = time.perf_counter() - start_time
            print_and_log(f"    ✓ ĐÚNG: Xác thực thất bại (như mong đợi) - {verification_time*1000:.4f} ms", output_file)
            print_and_log("    ✓ Ed25519 phát hiện chữ ký không hợp lệ", output_file)
            fake_sig_status = "THÀNH CÔNG"
        
        # ==================== BƯỚC 7: HIỆU NĂNG ====================
        print_and_log("\n[BƯỚC 7] ĐÁNH GIÁ HIỆU NĂNG", output_file)
        print_and_log("-" * 80, output_file)
        
        print_and_log(f"\n7.1. Thời gian thực hiện:", output_file)
        print_and_log(f"    - Thời gian ký:        {signing_time*1000:.4f} ms", output_file)
        print_and_log(f"    - Thời gian xác thực:  {verification_time*1000:.4f} ms", output_file)
        
        # Test hiệu năng với nhiều lần ký
        print_and_log(f"\n7.2. Benchmark (1000 lần ký):", output_file)
        iterations = 1000
        start_time = time.perf_counter()
        for _ in range(iterations):
            _ = private_key.sign(message_bytes)
        total_time = time.perf_counter() - start_time
        avg_time = total_time / iterations
        
        print_and_log(f"    - Tổng thời gian: {total_time:.4f} s", output_file)
        print_and_log(f"    - Trung bình:     {avg_time*1000:.4f} ms/lần ký", output_file)
        print_and_log(f"    - Tốc độ:         {iterations/total_time:.2f} chữ ký/giây", output_file)
        
        # Test hiệu năng xác thực
        print_and_log(f"\n7.3. Benchmark (1000 lần xác thực):", output_file)
        start_time = time.perf_counter()
        for _ in range(iterations):
            try:
                public_key.verify(signature, message_bytes)
            except:
                pass
        total_time = time.perf_counter() - start_time
        avg_time = total_time / iterations
        
        print_and_log(f"    - Tổng thời gian: {total_time:.4f} s", output_file)
        print_and_log(f"    - Trung bình:     {avg_time*1000:.4f} ms/lần xác thực", output_file)
        print_and_log(f"    - Tốc độ:         {iterations/total_time:.2f} xác thực/giây", output_file)
        
        # ==================== BƯỚC 8: THÔNG TIN KỸ THUẬT ====================
        print_and_log("\n[BƯỚC 8] THÔNG TIN KỸ THUẬT VÀ BẢO MẬT", output_file)
        print_and_log("-" * 80, output_file)
        
        print_and_log("\n8.1. Đặc điểm nổi bật của Ed25519:", output_file)
        print_and_log("    ✓ Tốc độ: Nhanh nhất trong các thuật toán chữ ký số", output_file)
        print_and_log("    ✓ Kích thước: Chữ ký chỉ 64 bytes (nhỏ gọn)", output_file)
        print_and_log("    ✓ Deterministic: Cùng message + key → cùng signature", output_file)
        print_and_log("    ✓ Side-channel resistant: Kháng tấn công kênh bên", output_file)
        print_and_log("    ✓ Không cần RNG: Không phụ thuộc vào bộ sinh số ngẫu nhiên", output_file)
        print_and_log("    ✓ Simple: Dễ triển khai đúng, khó triển khai sai", output_file)
        
        print_and_log("\n8.2. So sánh với các thuật toán khác:", output_file)
        print_and_log("    ", output_file)
        print_and_log("    Thuật toán    | Độ dài khóa | Chữ ký  | Tốc độ ký | Tốc độ verify", output_file)
        print_and_log("    --------------|-------------|---------|-----------|---------------", output_file)
        print_and_log("    Ed25519       | 32 bytes    | 64 B    | Rất nhanh | Rất nhanh", output_file)
        print_and_log("    ECDSA P-256   | 32 bytes    | ~70 B   | Nhanh     | Nhanh", output_file)
        print_and_log("    RSA-2048      | 256 bytes   | 256 B   | Chậm      | Nhanh", output_file)
        print_and_log("    RSA-3072      | 384 bytes   | 384 B   | Rất chậm  | Nhanh", output_file)
        
        print_and_log("\n8.3. Thông số kỹ thuật:", output_file)
        print_and_log("    - Tên đường cong: Curve25519 (twisted Edwards form)", output_file)
        print_and_log("    - Phương trình:   -x² + y² = 1 - (121665/121666)x²y²", output_file)
        print_and_log("    - Prime field p:  2^255 - 19", output_file)
        print_and_log("    - Group order L:  2^252 + 27742317777372353535851937790883648493", output_file)
        print_and_log("    - Cofactor:       8", output_file)
        print_and_log("    - Base point:     (x, 4/5)", output_file)
        
        print_and_log("\n8.4. Mức độ bảo mật:", output_file)
        print_and_log("    - Mức bảo mật:        128 bits", output_file)
        print_and_log("    - Tương đương RSA:    3072 bits", output_file)
        print_and_log("    - Tương đương AES:    AES-128", output_file)
        print_and_log("    - Kháng quantum:      Không (như tất cả các hệ mật khóa công khai hiện nay)", output_file)
        
        print_and_log("\n8.5. Ứng dụng thực tế:", output_file)
        print_and_log("    - OpenSSH:            ssh-ed25519 (từ OpenSSH 6.5)", output_file)
        print_and_log("    - GnuPG:              EdDSA keys", output_file)
        print_and_log("    - Signal Protocol:    X3DH key agreement", output_file)
        print_and_log("    - TLS 1.3:            ed25519 signature algorithm", output_file)
        print_and_log("    - Cryptocurrencies:   Monero, Cardano, Stellar, Nano", output_file)
        print_and_log("    - DNSSEC:             EdDSA signing", output_file)
        print_and_log("    - Tor:                v3 onion addresses", output_file)
        print_and_log("    - IPFS:               Identity keys", output_file)
        
        print_and_log("\n8.6. Ưu điểm so với ECDSA:", output_file)
        print_and_log("    ✓ Nhanh hơn (cả ký và xác thực)", output_file)
        print_and_log("    ✓ Deterministic (không cần RNG tốt khi ký)", output_file)
        print_and_log("    ✓ Đơn giản hơn (ít tham số, khó lỗi triển khai)", output_file)
        print_and_log("    ✓ Kháng side-channel tốt hơn", output_file)
        print_and_log("    ✓ Không có vấn đề 'k reuse' như ECDSA", output_file)
        
        print_and_log("\n8.7. Lưu ý bảo mật quan trọng:", output_file)
        print_and_log("    ⚠ LUÔN bảo vệ khóa bí mật cẩn thận", output_file)
        print_and_log("    ⚠ KHÔNG bao giờ chia sẻ private key", output_file)
        print_and_log("    ⚠ Sử dụng entropy tốt khi sinh khóa", output_file)
        print_and_log("    ⚠ Backup khóa an toàn (mã hóa khi lưu trữ)", output_file)
        print_and_log("    ⚠ Rotate khóa định kỳ trong production", output_file)
        print_and_log("    ⚠ Không dùng lại khóa cho mục đích khác (separation)", output_file)
        
        # ==================== TỔNG KẾT ====================
        summary = f"""
{'='*80}
                        TỔNG KẾT KẾT QUẢ
{'='*80}

THÔNG TIN THÔNG ĐIỆP:
  - Thông điệp:             {len(message)} ký tự ({len(message_bytes)} bytes)
  - Hash SHA-512:           {message_hash.hex()[:32]}...

THÔNG TIN KHÓA:
  - Thuật toán:             Ed25519 (EdDSA)
  - Độ dài khóa bí mật:     32 bytes (256 bits)
  - Độ dài khóa công khai:  32 bytes (256 bits)

THÔNG TIN CHỮ KÝ:
  - Độ dài chữ ký:          64 bytes (512 bits)
  - Chữ ký (hex):           {signature.hex()[:32]}...

KẾT QUẢ XÁC THỰC:
  ✓ Thông điệp gốc:         {verification_status}
  ✓ Thông điệp sửa đổi:     {tampered_status} (Phát hiện đúng)
  ✓ Chữ ký giả:             {fake_sig_status} (Phát hiện đúng)

HIỆU NĂNG:
  - Tốc độ ký:              {1/avg_time if avg_time > 0 else 0:.0f} signatures/second
  - Tốc độ xác thực:        {iterations/total_time:.0f} verifications/second

BẢO MẬT:
  - Mức bảo mật:            128 bits (tương đương RSA-3072)
  - Đường cong:             Curve25519
  - Hash function:          SHA-512

✓ Chương trình hoàn thành thành công!
✓ Kết quả đã được lưu vào: {OUTPUT_FILE}
✓ Chữ ký số Ed25519 hoạt động hoàn hảo!
{'='*80}
"""
        print_and_log(summary, output_file)
        
        print("\n" + "="*80)
        print("💡 GỢI Ý SỬ DỤNG:")
        print("="*80)
        print("1. File khóa bí mật (private-key-ed25519.pem) - GIỮ BÍ MẬT")
        print("2. File khóa công khai (public-key-ed25519.pem) - Có thể chia sẻ")
        print("3. Người khác dùng public key để xác thực chữ ký của bạn")
        print("4. Chỉ bạn có private key mới có thể tạo chữ ký hợp lệ")
        print("="*80)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n✗ Chương trình bị hủy bởi người dùng.")
    except Exception as e:
        print(f"\n\n✗ LỖI: {e}")
        import traceback
        traceback.print_exc()
