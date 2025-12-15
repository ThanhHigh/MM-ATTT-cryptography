"""
Sơ đồ xưng danh ECC (ECC Authentication Scheme)
================================================
Triển khai giao thức xưng danh dựa trên ECC với challenge-response
Giao thức Schnorr Identification Scheme trên đường cong Elliptic
"""

from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
import secrets
import time
import os

# ====================================================================================
# CÁC HẰNG SỐ VÀ ĐƯỜNG DẪN FILE
# ====================================================================================
PRIVATE_FILE_PEM = "private-key.pem"
PUBLIC_FILE_PEM = "public-key.pem"
OUTPUT_FILE = "../ket_qua/result.txt"

# ====================================================================================
# HÀM PHỤ TRỢ
# ====================================================================================

def log_output(message, output_lines):
    """In ra console và lưu vào danh sách để ghi file"""
    print(message)
    output_lines.append(message)

def point_to_string(point):
    """Chuyển điểm ECC thành chuỗi hex"""
    return f"({hex(point.x)}, {hex(point.y)})"

def hash_message(*args):
    """Hash các tham số thành một số nguyên"""
    h = SHA256.new()
    for arg in args:
        if isinstance(arg, int):
            h.update(arg.to_bytes((arg.bit_length() + 7) // 8, 'big'))
        elif isinstance(arg, str):
            h.update(arg.encode())
        elif hasattr(arg, 'x') and hasattr(arg, 'y'):  # ECC Point
            h.update(arg.x.to_bytes((arg.x.bit_length() + 7) // 8, 'big'))
            h.update(arg.y.to_bytes((arg.y.bit_length() + 7) // 8, 'big'))
    return int.from_bytes(h.digest(), 'big')

# ====================================================================================
# LỚP PROVER (NGƯỜI CHỨNG MINH)
# ====================================================================================

class Prover:
    """Người chứng minh danh tính (có khóa bí mật)"""
    
    def __init__(self, private_key_path):
        """Khởi tạo với khóa bí mật"""
        self.private_key = ECC.import_key(open(private_key_path, 'r').read())
        self.public_key = self.private_key.public_key()
        self.curve = self.private_key.curve
        
        # Lấy thông tin đường cong
        self.G = self.private_key.pointQ  # Generator point
        self.n = int(self.private_key._curve.order)  # Order của nhóm (chuyển sang int)
        self.d = int(self.private_key.d)  # Khóa bí mật (chuyển sang int)
        self.Q = self.public_key.pointQ  # Khóa công khai Q = d*G
        
    def generate_commitment(self):
        """
        BƯỚC 1: Tạo commitment
        - Chọn ngẫu nhiên r trong [1, n-1]
        - Tính R = r*G
        - Trả về R (commitment)
        """
        self.r = secrets.randbelow(self.n - 1) + 1
        self.R = self.r * self.G
        return self.R, self.r
    
    def generate_response(self, challenge):
        """
        BƯỚC 3: Tạo response
        - Nhận challenge c từ Verifier
        - Tính s = r + c*d (mod n)
        - Trả về s
        """
        self.c = challenge
        self.s = (self.r + self.c * self.d) % self.n
        return self.s

# ====================================================================================
# LỚP VERIFIER (NGƯỜI KIỂM TRA)
# ====================================================================================

class Verifier:
    """Người kiểm tra danh tính (có khóa công khai)"""
    
    def __init__(self, public_key_path):
        """Khởi tạo với khóa công khai"""
        self.public_key = ECC.import_key(open(public_key_path, 'r').read())
        self.Q = self.public_key.pointQ  # Q = d*G
        
        # Lấy thông tin đường cong
        # Sử dụng curve name để lấy thông tin
        if self.public_key.curve == 'NIST P-256':
            # Order của P-256
            self.n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
            # Generator point
            Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
            Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
            self.G = ECC.EccPoint(Gx, Gy, curve='P-256')
        else:
            raise ValueError(f"Curve {self.public_key.curve} not supported")
    
    def generate_challenge(self, R):
        """
        BƯỚC 2: Tạo challenge
        - Nhận R từ Prover
        - Tạo challenge c ngẫu nhiên hoặc hash(R, Q, message)
        - Trả về c
        """
        self.R = R
        # Tạo challenge ngẫu nhiên
        self.c = secrets.randbelow(self.n - 1) + 1
        # Hoặc có thể dùng hash để tạo challenge (Fiat-Shamir heuristic)
        # self.c = hash_message(R, self.Q, "authentication") % self.n
        return self.c
    
    def verify(self, s):
        """
        BƯỚC 4: Kiểm tra
        - Nhận s từ Prover
        - Kiểm tra: s*G == R + c*Q
        - Nếu đúng: chấp nhận, sai: từ chối
        """
        self.s = s
        
        # Tính s*G
        left_side = self.s * self.G
        
        # Tính R + c*Q
        right_side = self.R + (self.c * self.Q)
        
        # So sánh
        return left_side.x == right_side.x and left_side.y == right_side.y

# ====================================================================================
# CHƯƠNG TRÌNH CHÍNH
# ====================================================================================

def main():
    output_lines = []
    
    log_output("=" * 80, output_lines)
    log_output("SƠ ĐỒ XƯNG DANH ECC (ECC AUTHENTICATION SCHEME)", output_lines)
    log_output("Giao thức Schnorr trên đường cong Elliptic Curve", output_lines)
    log_output("=" * 80, output_lines)
    log_output("", output_lines)
    
    start_time = time.time()
    
    # ====================================================================================
    # KHỞI TẠO
    # ====================================================================================
    log_output("BƯỚC KHỞI TẠO", output_lines)
    log_output("-" * 80, output_lines)
    
    # Kiểm tra file khóa
    if not os.path.exists(PRIVATE_FILE_PEM) or not os.path.exists(PUBLIC_FILE_PEM):
        log_output("ERROR: Không tìm thấy file khóa!", output_lines)
        log_output("Vui lòng chạy sinh_key_ECC.py trước.", output_lines)
        return
    
    # Khởi tạo Prover và Verifier
    prover = Prover(PRIVATE_FILE_PEM)
    verifier = Verifier(PUBLIC_FILE_PEM)
    
    log_output(f"Đường cong: {prover.curve}", output_lines)
    log_output(f"Order của nhóm (n): {hex(prover.n)}", output_lines)
    log_output(f"Khóa bí mật (d): {hex(prover.d)}", output_lines)
    log_output(f"Khóa công khai (Q): {point_to_string(prover.Q)}", output_lines)
    log_output("", output_lines)
    
    # ====================================================================================
    # GIAO THỨC XƯNG DANH
    # ====================================================================================
    log_output("GIAO THỨC XƯNG DANH (3 BƯỚC)", output_lines)
    log_output("=" * 80, output_lines)
    log_output("", output_lines)
    
    # BƯỚC 1: PROVER TẠO COMMITMENT
    log_output("BƯỚC 1: PROVER TẠO COMMITMENT", output_lines)
    log_output("-" * 80, output_lines)
    
    R, r = prover.generate_commitment()
    log_output(f"Prover chọn ngẫu nhiên r: {hex(r)}", output_lines)
    log_output(f"Prover tính R = r*G: {point_to_string(R)}", output_lines)
    log_output("Prover gửi R cho Verifier", output_lines)
    log_output("", output_lines)
    
    # BƯỚC 2: VERIFIER TẠO CHALLENGE
    log_output("BƯỚC 2: VERIFIER TẠO CHALLENGE", output_lines)
    log_output("-" * 80, output_lines)
    
    c = verifier.generate_challenge(R)
    log_output(f"Verifier nhận R: {point_to_string(R)}", output_lines)
    log_output(f"Verifier tạo challenge c: {hex(c)}", output_lines)
    log_output("Verifier gửi c cho Prover", output_lines)
    log_output("", output_lines)
    
    # BƯỚC 3: PROVER TẠO RESPONSE
    log_output("BƯỚC 3: PROVER TẠO RESPONSE", output_lines)
    log_output("-" * 80, output_lines)
    
    s = prover.generate_response(c)
    log_output(f"Prover nhận challenge c: {hex(c)}", output_lines)
    log_output(f"Prover tính s = (r + c*d) mod n: {hex(s)}", output_lines)
    log_output("Prover gửi s cho Verifier", output_lines)
    log_output("", output_lines)
    
    # BƯỚC 4: VERIFIER KIỂM TRA
    log_output("BƯỚC 4: VERIFIER KIỂM TRA", output_lines)
    log_output("-" * 80, output_lines)
    
    log_output(f"Verifier nhận s: {hex(s)}", output_lines)
    log_output("Verifier kiểm tra phương trình: s*G == R + c*Q", output_lines)
    log_output("", output_lines)
    
    # Tính toán chi tiết
    left_side = s * verifier.G
    right_side = R + (c * verifier.Q)
    
    log_output("Chi tiết tính toán:", output_lines)
    log_output(f"  Vế trái (s*G): {point_to_string(left_side)}", output_lines)
    log_output(f"  Vế phải (R + c*Q): {point_to_string(right_side)}", output_lines)
    log_output("", output_lines)
    
    # Kiểm tra
    is_valid = verifier.verify(s)
    
    log_output("=" * 80, output_lines)
    if is_valid:
        log_output("✓ KẾT QUẢ: XÁC THỰC THÀNH CÔNG!", output_lines)
        log_output("Prover đã chứng minh được danh tính của mình.", output_lines)
    else:
        log_output("✗ KẾT QUẢ: XÁC THỰC THẤT BẠI!", output_lines)
        log_output("Prover không chứng minh được danh tính.", output_lines)
    log_output("=" * 80, output_lines)
    log_output("", output_lines)
    
    # ====================================================================================
    # PHÂN TÍCH BẢO MẬT
    # ====================================================================================
    log_output("PHÂN TÍCH BẢO MẬT", output_lines)
    log_output("-" * 80, output_lines)
    log_output("1. Tính đúng đắn (Completeness):", output_lines)
    log_output("   - Nếu Prover biết d, luôn xác thực thành công", output_lines)
    log_output("   - Chứng minh: s*G = (r + c*d)*G = r*G + c*d*G = R + c*Q ✓", output_lines)
    log_output("", output_lines)
    
    log_output("2. Tính an toàn (Soundness):", output_lines)
    log_output("   - Nếu Prover không biết d, xác suất lừa Verifier rất nhỏ (1/n)", output_lines)
    log_output("   - Prover phải đoán đúng challenge c trước khi nhận được", output_lines)
    log_output("", output_lines)
    
    log_output("3. Tính zero-knowledge:", output_lines)
    log_output("   - Verifier không học được thông tin về khóa bí mật d", output_lines)
    log_output("   - Chỉ biết s = r + c*d, nhưng không thể tính d từ đó", output_lines)
    log_output("", output_lines)
    
    log_output("4. Độ an toàn:", output_lines)
    log_output(f"   - Dựa trên bài toán logarit rời rạc trên đường cong elliptic (ECDLP)", output_lines)
    log_output(f"   - Độ dài khóa: {prover.n.bit_length()} bits", output_lines)
    log_output(f"   - Độ phức tạp tấn công: O(√n) ≈ 2^{prover.n.bit_length()//2} operations", output_lines)
    log_output("", output_lines)
    
    # ====================================================================================
    # THỐNG KÊ HIỆU NĂNG
    # ====================================================================================
    end_time = time.time()
    execution_time = end_time - start_time
    
    log_output("THỐNG KÊ HIỆU NĂNG", output_lines)
    log_output("-" * 80, output_lines)
    log_output(f"Thời gian thực thi: {execution_time:.6f} giây", output_lines)
    log_output(f"Số lần nhân điểm ECC: 4 (R, c*Q, s*G, R+c*Q)", output_lines)
    log_output(f"Kích thước thông tin truyền:", output_lines)
    log_output(f"  - Commitment R: {(prover.n.bit_length() * 2) // 8} bytes", output_lines)
    log_output(f"  - Challenge c: {prover.n.bit_length() // 8} bytes", output_lines)
    log_output(f"  - Response s: {prover.n.bit_length() // 8} bytes", output_lines)
    log_output(f"  - Tổng: {(prover.n.bit_length() * 4) // 8} bytes", output_lines)
    log_output("", output_lines)
    
    # ====================================================================================
    # SO SÁNH VỚI CÁC PHƯƠNG PHÁP KHÁC
    # ====================================================================================
    log_output("SO SÁNH VỚI CÁC SƠ ĐỒ XƯNG DANH KHÁC", output_lines)
    log_output("-" * 80, output_lines)
    log_output("1. RSA-based authentication:", output_lines)
    log_output("   - Ưu điểm ECC: Khóa ngắn hơn (256-bit ECC ~ 3072-bit RSA)", output_lines)
    log_output("   - Ưu điểm ECC: Nhanh hơn trong phép toán", output_lines)
    log_output("", output_lines)
    
    log_output("2. Password-based authentication:", output_lines)
    log_output("   - Ưu điểm ECC: Không cần lưu trữ mật khẩu", output_lines)
    log_output("   - Ưu điểm ECC: Không sợ tấn công từ điển", output_lines)
    log_output("", output_lines)
    
    log_output("3. Certificate-based (PKI):", output_lines)
    log_output("   - Ưu điểm ECC: Không cần cơ sở hạ tầng phức tạp", output_lines)
    log_output("   - Nhược điểm: Cần tương tác nhiều bước", output_lines)
    log_output("", output_lines)
    
    log_output("=" * 80, output_lines)
    log_output("HOÀN THÀNH CHƯƠNG TRÌNH SƠ ĐỒ XƯNG DANH ECC", output_lines)
    log_output("=" * 80, output_lines)
    
    # ====================================================================================
    # GHI KẾT QUẢ RA FILE
    # ====================================================================================
    output_dir = os.path.dirname(OUTPUT_FILE)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines))
    
    print(f"\n✓ Đã lưu kết quả vào file: {OUTPUT_FILE}")

# ====================================================================================
# CHẠY CHƯƠNG TRÌNH
# ====================================================================================

if __name__ == "__main__":
    main()
