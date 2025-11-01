from Crypto.Util import number
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import random

PUBLIC_FILE = "public-key.pem"
PRIVATE_FILE = "private-key.pem"

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
    message = b'Meet at midnight'
    print("==============================================")
    print(f"Hệ mật RSA cơ bản - Kích thước khóa: 1024 bits")
    print(f"Thông điệp gốc: {message}")
    print("==============================================")
    
    # 2. Sinh khóa
    public_key = RSA.import_key(open(PUBLIC_FILE).read())
    private_key = RSA.import_key(open(PRIVATE_FILE).read())
    n = public_key.n
    e = public_key.e
    d = private_key.d
    
    print("\n[THÔNG TIN KHÓA]")
    print(f"Modulus n (công khai): \n{n}")
    print(f"Khóa công khai e (công khai): \n{e}")
    print(f"Khóa bí mật d (bí mật): \n{d}")
    
    # 3. Mã hóa
    print("\n[QUÁ TRÌNH MÃ HÓA]")
    # can_encrypt = public_key.can_encrypt()
    cipher_pub = PKCS1_OAEP.new(public_key)
    ciphertext = cipher_pub.encrypt(message)
    ciphertext_int = int.from_bytes(ciphertext, byteorder='big')
    # print(f"Bản mã CipherText: \n{ciphertext}")
    print(f"Bản mã CipherText (dạng số nguyên): \n{ciphertext_int}")

    # 4. Giải mã
    print("\n[QUÁ TRÌNH GIẢI MÃ]")
    # thong_diep_giai_ma = giai_ma(ban_ma_so, private_key)
    cipher_priv = PKCS1_OAEP.new(private_key)
    message_decrypted = cipher_priv.decrypt(ciphertext)
    print(f"Thông điệp sau giải mã (dạng byte): \n{message_decrypted}")
    
    # # 5. Kiểm tra kết quả
    # print("\n[KIỂM TRA]")
    # if thong_diep_goc == thong_diep_giai_ma:
    #     print("Mã hóa và Giải mã THÀNH CÔNG! ✅")
    # else:
    #     print("Lỗi trong quá trình Mã hóa/Giải mã! ❌")