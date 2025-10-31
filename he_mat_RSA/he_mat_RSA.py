from Crypto.Util import number
import random

# --- HÀM TOÁN HỌC CƠ BẢN VÀ NÂNG CAO ---

def tao_so_nguyen_to(bits):
    """
    Sử dụng PyCryptodome để tạo một số nguyên tố ngẫu nhiên có độ dài 'bits'.
    Bỏ qua randfunc để sử dụng nguồn ngẫu nhiên an toàn mặc định của PyCryptodome.
    """
    return number.getPrime(bits) # Đã bỏ randfunc=...

def nghich_dao_modulo(a, m):
    """
    Sử dụng PyCryptodome để tính số nghịch đảo modulo:
    Tìm x sao cho a*x ≡ 1 (mod m).
    Trong RSA, a = e và m = phi_n.
    """
    try:
        # number.inverse(a, m) thực hiện thuật toán Euclide mở rộng
        return number.inverse(a, m)
    except ValueError:
        # Nếu không tìm được nghịch đảo (UCLN(a, m) != 1)
        return None

def luy_thua_modulo(co_so, so_mu, modulo):
    """
    Tính lũy thừa modulo (a^b mod m). Python hỗ trợ sẵn phép toán này 
    rất hiệu quả với số lớn bằng hàm pow() 3 tham số.
    Đây là phép toán cốt lõi trong Mã hóa và Giải mã.
    """
    return pow(co_so, so_mu, modulo)

# --- QUY TRÌNH HỆ MẬT RSA ---

def sinh_khoa(bit_length=1024):
    """
    Sinh khóa công khai (n, e) và khóa bí mật (n, d).
    Độ dài bit_length đề xuất là 1024 hoặc 2048.
    """
    print(f"1. Sinh 2 số nguyên tố p và q có {bit_length} bits...")
    p = tao_so_nguyen_to(bit_length)
    q = tao_so_nguyen_to(bit_length)
    
    # Đảm bảo p và q khác nhau
    while p == q:
        q = tao_so_nguyen_to(bit_length)

    # 2. Tính n (Modulus)
    n = p * q
    
    # 3. Tính phi(n) = (p-1)(q-1)
    phi_n = (p - 1) * (q - 1)
    
    # 4. Chọn e (Khóa công khai)
    # Thường chọn e = 65537 vì đây là số nguyên tố Fermat F4, 
    # giúp phép tính lũy thừa modulo nhanh hơn.
    e = 65537
    
    # 5. Tính d (Khóa bí mật)
    print("2. Tính khóa bí mật d...")
    d = nghich_dao_modulo(e, phi_n)
    
    return ((n, e), (n, d), p, q) # (Khóa công khai, Khóa bí mật, p, q)

def ma_hoa(thong_diep, public_key):
    """
    Mã hóa bản rõ M thành bản mã C: C = M^e mod n
    """
    n, e = public_key
    # Chuyển chuỗi thông điệp thành số nguyên lớn
    # Sử dụng 'big' endian để đảm bảo số lớn nhất có thể
    M = int.from_bytes(thong_diep.encode('utf-8'), byteorder='big')
    
    if M >= n:
        raise ValueError("Thông điệp quá lớn, không thể mã hóa với khóa này.")
        
    C = luy_thua_modulo(M, e, n)
    return C

def giai_ma(ban_ma, private_key):
    """
    Giải mã bản mã C thành bản rõ M: M = C^d mod n
    """
    n, d = private_key
    
    # Tính M = C^d mod n
    M_int = luy_thua_modulo(ban_ma, d, n)
    
    # Chuyển số nguyên lớn M thành chuỗi byte, sau đó giải mã về chuỗi ký tự
    byte_length = (M_int.bit_length() + 7) // 8
    M_bytes = M_int.to_bytes(byte_length, byteorder='big')
    
    # Đôi khi có ký tự padding rỗng ở đầu, ta có thể strip nó đi
    thong_diep = M_bytes.decode('utf-8').lstrip('\x00')
    return thong_diep

# --- CHẠY CHƯƠNG TRÌNH ---
if __name__ == '__main__':
    # 1. Cấu hình
    BIT_SIZE = 128  # Dùng số bit nhỏ (128) để chạy nhanh và dễ in ra. 
                    # Trong thực tế, cần dùng 1024, 2048 hoặc 4096.
    thong_diep_goc = "Meet at midnight"
    print("==============================================")
    print(f"Hệ mật RSA cơ bản - Kích thước khóa: {BIT_SIZE} bits")
    print(f"Thông điệp gốc: {thong_diep_goc}")
    print("==============================================")
    
    # 2. Sinh khóa
    public_key, private_key, p, q = sinh_khoa(BIT_SIZE)
    n, e = public_key
    _, d = private_key
    
    print("\n[THÔNG TIN KHÓA]")
    print(f"Số nguyên tố p: \n{p}")
    print(f"Số nguyên tố q: \n{q}")
    print(f"Modulus n (công khai): \n{n}")
    print(f"Khóa công khai e (công khai): \n{e}")
    print(f"Khóa bí mật d (bí mật): \n{d}")
    
    # 3. Mã hóa
    print("\n[QUÁ TRÌNH MÃ HÓA]")
    ban_ma_so = ma_hoa(thong_diep_goc, public_key)
    print(f"Bản mã C (số nguyên lớn): \n{ban_ma_so}")
    
    # 4. Giải mã
    print("\n[QUÁ TRÌNH GIẢI MÃ]")
    thong_diep_giai_ma = giai_ma(ban_ma_so, private_key)
    print(f"Thông điệp sau giải mã: \n{thong_diep_giai_ma}")
    
    # 5. Kiểm tra kết quả
    print("\n[KIỂM TRA]")
    if thong_diep_goc == thong_diep_giai_ma:
        print("Mã hóa và Giải mã THÀNH CÔNG! ✅")
    else:
        print("Lỗi trong quá trình Mã hóa/Giải mã! ❌")