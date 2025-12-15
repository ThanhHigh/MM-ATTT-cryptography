"""
Chương trình triển khai Sơ đồ Chữ ký số ElGamal
"""

import json
import base64
import hashlib
import secrets
from math import gcd


def load_public_key(filename):
    """Đọc khóa công khai từ file PEM"""
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Lấy nội dung base64 giữa header và footer
    lines = content.split('\n')
    b64_content = ''.join(line.strip() for line in lines if line and not line.startswith('-----'))
    
    # Giải mã base64 và parse JSON
    json_str = base64.b64decode(b64_content).decode('utf-8')
    key_data = json.loads(json_str)
    
    return {
        'p': int(key_data['p']),
        'g': int(key_data['g']),
        'y': int(key_data['y'])
    }


def load_private_key(filename):
    """Đọc khóa riêng từ file PEM"""
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Lấy nội dung base64
    lines = content.split('\n')
    b64_content = ''.join(line.strip() for line in lines if line and not line.startswith('-----'))
    
    # Giải mã base64 và parse JSON
    json_str = base64.b64decode(b64_content).decode('utf-8')
    key_data = json.loads(json_str)
    
    return {
        'p': int(key_data['p']),
        'g': int(key_data['g']),
        'y': int(key_data['y']),
        'x': int(key_data['x'])
    }


def hash_message(message):
    """Hash thông điệp sử dụng SHA-256"""
    return int(hashlib.sha256(message.encode('utf-8')).hexdigest(), 16)


def mod_inverse(a, m):
    """Tính nghịch đảo modulo sử dụng Extended Euclidean Algorithm"""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y
    
    gcd_val, x, _ = extended_gcd(a % m, m)
    if gcd_val != 1:
        raise ValueError("Nghịch đảo modulo không tồn tại")
    return (x % m + m) % m


def generate_random_k(p):
    """Sinh số ngẫu nhiên k sao cho gcd(k, p-1) = 1"""
    p_minus_1 = p - 1
    while True:
        k = secrets.randbelow(p_minus_1 - 2) + 2  # k trong khoảng [2, p-2]
        if gcd(k, p_minus_1) == 1:
            return k


def sign_message(message, private_key):
    """
    Ký thông điệp sử dụng sơ đồ chữ ký ElGamal
    
    Input:
        - message: Thông điệp cần ký
        - private_key: Dict chứa {p, g, y, x}
    
    Output:
        - (r, s): Chữ ký số
    """
    p = private_key['p']
    g = private_key['g']
    x = private_key['x']
    
    print("\n" + "="*80)
    print("BƯỚC 1: CHUẨN BỊ KÝ THÔNG ĐIỆP")
    print("="*80)
    print(f"Thông điệp gốc: {message}")
    
    # Bước 1: Hash thông điệp
    print("\n--- Hash thông điệp ---")
    h_m = hash_message(message)
    print(f"Hash(message) = SHA-256('{message}')")
    print(f"H(m) = {h_m}")
    print(f"Số bit của H(m): {h_m.bit_length()}")
    
    # Bước 2: Sinh k ngẫu nhiên
    print("\n--- Sinh số ngẫu nhiên k ---")
    k = generate_random_k(p)
    print(f"k = {k}")
    print(f"gcd(k, p-1) = gcd({k}, {p-1}) = {gcd(k, p-1)}")
    print(f"✓ k hợp lệ (gcd = 1)")
    
    # Bước 3: Tính r = g^k mod p
    print("\n--- Tính r = g^k mod p ---")
    r = pow(g, k, p)
    print(f"r = {g}^{k} mod {p}")
    print(f"r = {r}")
    
    # Bước 4: Tính s = (H(m) - x*r) * k^(-1) mod (p-1)
    print("\n--- Tính s = (H(m) - x*r) * k^(-1) mod (p-1) ---")
    
    # Tính k^(-1) mod (p-1)
    k_inv = mod_inverse(k, p - 1)
    print(f"k^(-1) mod (p-1) = {k_inv}")
    print(f"Kiểm tra: k * k^(-1) mod (p-1) = {(k * k_inv) % (p - 1)} (phải bằng 1)")
    
    # Tính (H(m) - x*r) mod (p-1)
    h_m_reduced = h_m % (p - 1)
    print(f"\nH(m) mod (p-1) = {h_m_reduced}")
    x_r = (x * r) % (p - 1)
    print(f"x * r mod (p-1) = {x_r}")
    numerator = (h_m_reduced - x_r) % (p - 1)
    print(f"(H(m) - x*r) mod (p-1) = {numerator}")
    
    # Tính s
    s = (numerator * k_inv) % (p - 1)
    print(f"\ns = {numerator} * {k_inv} mod (p-1)")
    print(f"s = {s}")
    
    print("\n" + "="*80)
    print("✓ KÝ THÔNG ĐIỆP THÀNH CÔNG!")
    print("="*80)
    print(f"Chữ ký: (r, s) = ({r}, {s})")
    
    return (r, s)


def verify_signature(message, signature, public_key):
    """
    Xác minh chữ ký ElGamal
    
    Input:
        - message: Thông điệp gốc
        - signature: Tuple (r, s)
        - public_key: Dict chứa {p, g, y}
    
    Output:
        - True nếu chữ ký hợp lệ, False nếu không
    """
    r, s = signature
    p = public_key['p']
    g = public_key['g']
    y = public_key['y']
    
    print("\n" + "="*80)
    print("BƯỚC 2: XÁC MINH CHỮ KÝ")
    print("="*80)
    print(f"Thông điệp: {message}")
    print(f"Chữ ký nhận được: (r, s) = ({r}, {s})")
    
    # Kiểm tra điều kiện: 0 < r < p và 0 < s < p-1
    print("\n--- Kiểm tra điều kiện chữ ký ---")
    print(f"Kiểm tra 0 < r < p: {0 < r < p}")
    print(f"Kiểm tra 0 < s < p-1: {0 < s < p-1}")
    
    if not (0 < r < p and 0 < s < p - 1):
        print("✗ Chữ ký không hợp lệ (vi phạm điều kiện)")
        return False
    
    # Hash thông điệp
    print("\n--- Hash thông điệp ---")
    h_m = hash_message(message)
    print(f"H(m) = {h_m}")
    
    # Tính vế trái: y^r * r^s mod p
    print("\n--- Tính vế trái: y^r * r^s mod p ---")
    y_r = pow(y, r, p)
    print(f"y^r mod p = {y}^{r} mod {p}")
    print(f"y^r mod p = {y_r}")
    
    r_s = pow(r, s, p)
    print(f"\nr^s mod p = {r}^{s} mod {p}")
    print(f"r^s mod p = {r_s}")
    
    left_side = (y_r * r_s) % p
    print(f"\nVế trái = (y^r * r^s) mod p = {left_side}")
    
    # Tính vế phải: g^H(m) mod p
    print("\n--- Tính vế phải: g^H(m) mod p ---")
    right_side = pow(g, h_m, p)
    print(f"Vế phải = g^H(m) mod p = {g}^{h_m} mod {p}")
    print(f"Vế phải = {right_side}")
    
    # So sánh hai vế
    print("\n--- So sánh kết quả ---")
    print(f"Vế trái  = {left_side}")
    print(f"Vế phải = {right_side}")
    print(f"Bằng nhau? {left_side == right_side}")
    
    is_valid = (left_side == right_side)
    
    print("\n" + "="*80)
    if is_valid:
        print("✓ CHỮ KÝ HỢP LỆ!")
    else:
        print("✗ CHỮ KÝ KHÔNG HỢP LỆ!")
    print("="*80)
    
    return is_valid


def save_signature(signature, filename, message, verification_results=None):
    """Lưu chữ ký và kết quả xác minh vào file"""
    r, s = signature
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write("CHƯƠNG TRÌNH CHỮ KÝ SỐ ELGAMAL\n")
        f.write("="*80 + "\n\n")
        
        f.write(f"Thông điệp gốc: {message}\n\n")
        
        f.write("Chữ ký ElGamal:\n")
        f.write(f"  r = {r}\n")
        f.write(f"  s = {s}\n")
        
        if verification_results:
            f.write("\n" + "="*80 + "\n")
            f.write("KẾT QUẢ XÁC MINH\n")
            f.write("="*80 + "\n")
            
            for i, result in enumerate(verification_results, 1):
                f.write(f"\nThực nghiệm {i}: {result['title']}\n")
                f.write("-"*80 + "\n")
                f.write(f"Thông điệp: {result['message']}\n")
                f.write(f"Kết quả: {'✓ HỢP LỆ' if result['valid'] else '✗ KHÔNG HỢP LỆ'}\n")
                if 'note' in result:
                    f.write(f"Ghi chú: {result['note']}\n")
        
        f.write("\n" + "="*80 + "\n")


def main():
    """Chương trình chính"""
    print("\n")
    print("╔" + "="*78 + "╗")
    print("║" + " "*20 + "CHƯƠNG TRÌNH CHỮ KÝ SỐ ELGAMAL" + " "*28 + "║")
    print("╚" + "="*78 + "╝")
    
    # Đọc khóa
    print("\n┌─ ĐỌC KHÓA TỪ FILE ─────────────────────────────────────────────────────┐")
    try:
        private_key = load_private_key("private-key.pem")
        public_key = load_public_key("public-key.pem")
        
        print("✓ Đọc khóa riêng từ: private-key.pem")
        print("✓ Đọc khóa công khai từ: public-key.pem")
        
        print(f"\nThông số khóa:")
        print(f"  - Số nguyên tố p: {private_key['p']} ")
        print(f"  - Phần tử sinh g: {private_key['g']}")
        print(f"  - Khóa công khai y: {private_key['y']}")
        print(f"  - Khóa riêng x: {private_key['x']}")
        print("└" + "─"*76 + "┘")
    except Exception as e:
        print(f"✗ Lỗi khi đọc khóa: {e}")
        return
    
    # Nhập thông điệp
    print("\n┌─ NHẬP THÔNG ĐIỆP ──────────────────────────────────────────────────────┐")
    message = input("Nhập thông điệp cần ký: ").strip()
    if not message:
        message = "Hello, this is a test message for ElGamal digital signature!"
        print(f"(Sử dụng thông điệp mặc định: {message})")
    print("└" + "─"*76 + "┘")
    
    # Ký thông điệp
    try:
        signature = sign_message(message, private_key)
        
    except Exception as e:
        print(f"\n✗ Lỗi khi ký thông điệp: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Xác minh chữ ký
    verification_results = []
    
    try:
        # Thực nghiệm 1: Xác minh với thông điệp ĐÚNG
        print("\n" + "="*80)
        print("THỰC NGHIỆM 1: XÁC MINH VỚI THÔNG ĐIỆP ĐÚNG")
        print("="*80)
        print(f"Xác minh với thông điệp gốc: '{message}'")
        is_valid_original = verify_signature(message, signature, public_key)
        
        verification_results.append({
            'title': 'Xác minh với thông điệp ĐÚNG',
            'message': message,
            'valid': is_valid_original,
            'note': 'Đây là thông điệp gốc được ký, kết quả phải là HỢP LỆ'
        })
        
        # Thực nghiệm 2: Xác minh với thông điệp SAI
        print("\n" + "="*80)
        print("THỰC NGHIỆM 2: XÁC MINH VỚI THÔNG ĐIỆP SAI")
        print("="*80)
        fake_message = message + " (modified)"
        print(f"Xác minh với thông điệp giả mạo: '{fake_message}'")
        is_valid_fake = verify_signature(fake_message, signature, public_key)
        
        verification_results.append({
            'title': 'Xác minh với thông điệp SAI',
            'message': fake_message,
            'valid': is_valid_fake,
            'note': 'Thông điệp đã bị thay đổi, kết quả phải là KHÔNG HỢP LỆ'
        })
        
        # Lưu chữ ký và kết quả xác minh
        output_file = "../ket_qua/chu_ky_ElGamal.txt"
        save_signature(signature, output_file, message, verification_results)
        print(f"\n✓ Chữ ký và kết quả xác minh đã được lưu vào: {output_file}")
        
    except Exception as e:
        print(f"\n✗ Lỗi khi xác minh: {e}")
        import traceback
        traceback.print_exc()
        return
    
    print("\n" + "="*80)
    print("CHƯƠNG TRÌNH KẾT THÚC")
    print("="*80)


if __name__ == "__main__":
    main()
