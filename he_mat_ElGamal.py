from Crypto.Util import number
from Crypto import Random

# --- HÀM TOÁN HỌC VÀ TIỆN ÍCH ---

def tao_so_nguyen_to(bits):
    """Tạo số nguyên tố lớn p có 'bits'."""
    return number.getPrime(bits)

def luy_thua_modulo(co_so, so_mu, modulo):
    """Tính lũy thừa modulo: a^b mod m."""
    return pow(co_so, so_mu, modulo)

def nghich_dao_modulo(a, m):
    """Tính số nghịch đảo modulo: a^-1 mod m."""
    return number.inverse(a, m)

def get_generator(p):
    """
    Tìm phần tử sinh g của Zp* (đơn giản hóa: tìm một phần tử có bậc cao). 
    Trong thực tế, việc chọn g cần đảm bảo nó là phần tử sinh. 
    Để đơn giản và đảm bảo an toàn, thường chọn p là số nguyên tố Sophie Germain
    và q = (p-1)/2 cũng là số nguyên tố. Ở đây, ta chỉ tìm một phần tử sinh đơn giản.
    """
    q = (p - 1) // 2 # Giả sử p là số nguyên tố Sophie Germain, p=2q+1
    
    # Thử các giá trị g từ 2 cho đến p-2
    for g in range(2, p - 1):
        # Kiểm tra xem g có phải là phần tử sinh của nhóm con cấp q hay không (g^q != 1 mod p)
        # hoặc g là phần tử sinh của toàn bộ Zp* (g^((p-1)/2) != 1 mod p)
        # Nếu g^q != 1 mod p và g^2 != 1 mod p, thì g có cấp là p-1
        if pow(g, q, p) != 1 and pow(g, 2, p) != 1:
            return g
    
    # Trường hợp không tìm được (rất hiếm với số lớn)
    return 2 

# --- QUY TRÌNH HỆ MẬT ELGAMAL ---

def sinh_khoa_elgamal(bit_length=128):
    """
    Sinh khóa công khai (p, g, y) và khóa bí mật (x).
    """
    print(f"1. Sinh số nguyên tố lớn p có {bit_length} bits...")
    p = tao_so_nguyen_to(bit_length)
    
    # 2. Chọn phần tử sinh g
    print("2. Tìm phần tử sinh g...")
    g = get_generator(p)
    
    # 3. Chọn khóa bí mật x (1 < x < p-1)
    # SỬA LỖI: Thay thế number.randrange bằng number.getRandomRange
    x = number.getRandomRange(2, p) # Phạm vi [2, p-1]
    
    # 4. Tính khóa công khai y = g^x mod p
    print("3. Tính khóa công khai y...")
    y = luy_thua_modulo(g, x, p)
    
    public_key = (p, g, y)
    private_key = x
    
    return (public_key, private_key)

def ma_hoa_elgamal(thong_diep, public_key):
    """
    Mã hóa bản rõ M thành bản mã (C1, C2).
    """
    p, g, y = public_key
    
    # 1. Chuyển chuỗi thông điệp thành số nguyên lớn M
    M = int.from_bytes(thong_diep.encode('utf-8'), byteorder='big')
    
    if M >= p:
        raise ValueError("Thông điệp quá lớn. M phải < p.")
        
    # 2. Chọn số ngẫu nhiên k (khóa tạm thời)
    # SỬA LỖI: Thay thế number.randrange bằng number.getRandomRange
    k = number.getRandomRange(2, p) # Phạm vi [2, p-1]
    
    # ... (phần còn lại của hàm ma_hoa_elgamal giữ nguyên)
    # 3. Tính C1 = g^k mod p
    C1 = luy_thua_modulo(g, k, p)
    
    # 4. Tính S = y^k mod p (Khóa dùng chung)
    S = luy_thua_modulo(y, k, p) 
    
    # 5. Tính C2 = M * S mod p
    C2 = (M * S) % p
    
    return (C1, C2)

def giai_ma_elgamal(ban_ma, private_key, public_key):
    """
    Giải mã bản mã (C1, C2) thành bản rõ M.
    M = C2 * (C1^x)^-1 mod p
    """
    C1, C2 = ban_ma
    p, g, y = public_key # Cần p để tính modulo
    x = private_key
    
    # 1. Tính S = C1^x mod p
    S = luy_thua_modulo(C1, x, p)
    
    # 2. Tính S_inv = S^-1 mod p (Nghịch đảo modulo)
    S_inv = nghich_dao_modulo(S, p)
    
    # 3. Tính M_int = C2 * S_inv mod p
    M_int = (C2 * S_inv) % p
    
    # 4. Chuyển số nguyên lớn M_int thành chuỗi
    byte_length = (M_int.bit_length() + 7) // 8
    M_bytes = M_int.to_bytes(byte_length, byteorder='big')
    
    # Giải mã về chuỗi ký tự, loại bỏ ký tự padding rỗng
    thong_diep = M_bytes.decode('utf-8').lstrip('\x00')
    return thong_diep

# --- CHẠY CHƯƠNG TRÌNH ---
if __name__ == '__main__':
    # 1. Cấu hình
    BIT_SIZE = 128  # Dùng số bit nhỏ (128) để chạy nhanh. Thực tế cần 2048/3072.
    thong_diep_goc = "Meet at midnight"
    print("==============================================")
    print(f"Hệ mật ElGamal cơ bản - Kích thước khóa: {BIT_SIZE} bits")
    print(f"Thông điệp gốc: {thong_diep_goc}")
    print("==============================================")
    
    # 2. Sinh khóa
    public_key, private_key = sinh_khoa_elgamal(BIT_SIZE)
    p, g, y = public_key
    x = private_key
    
    print("\n[THÔNG TIN KHÓA]")
    print(f"Số nguyên tố p (công khai): \n{p}")
    print(f"Phần tử sinh g (công khai): \n{g}")
    print(f"Khóa công khai y (công khai): \n{y}")
    print(f"Khóa bí mật x (bí mật): \n{x}")
    
    # 3. Mã hóa
    print("\n[QUÁ TRÌNH MÃ HÓA]")
    C1, C2 = ma_hoa_elgamal(thong_diep_goc, public_key)
    print(f"Thành phần C1 (số nguyên lớn): \n{C1}")
    print(f"Thành phần C2 (số nguyên lớn): \n{C2}")
    
    # 4. Giải mã
    print("\n[QUÁ TRÌNH GIẢI MÃ]")
    thong_diep_giai_ma = giai_ma_elgamal((C1, C2), private_key, public_key)
    print(f"Thông điệp sau giải mã: \n{thong_diep_giai_ma}")
    
    # 5. Kiểm tra kết quả
    print("\n[KIỂM TRA]")
    if thong_diep_goc == thong_diep_giai_ma:
        print("Mã hóa và Giải mã THÀNH CÔNG! ✅")
    else:
        print("Lỗi trong quá trình Mã hóa/Giải mã! ❌")