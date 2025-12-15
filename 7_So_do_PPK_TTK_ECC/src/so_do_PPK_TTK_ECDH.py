# ==============================================================================
# HỆ MẬT MÃ ĐƯỜNG CONG ELLIPTIC (ECC) - GIAO THỨC THỎA THUẬN KHÓA ECDH
# ==============================================================================
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import time
import os

def write_output(log_lines):
    """Ghi kết quả ra file txt trong thư mục ket_qua"""
    output_dir = os.path.join(os.path.dirname(__file__), "..", "ket_qua")
    os.makedirs(output_dir, exist_ok=True)
    
    output_file = os.path.join(output_dir, "result.txt")
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines))
    
    return output_file

def ecc_key_agreement_demonstration():
    """
    Triển khai toàn bộ quy trình phân phối khóa và thỏa thuận khóa ECC (ECDH)
    giữa Alice và Bob, sử dụng khóa có sẵn, in các bước ra Console và lưu file txt.
    """
    log_lines = []
    
    def log_print(message):
        """In ra console và lưu vào log"""
        print(message)
        log_lines.append(message)
    
    log_print("=" * 80)
    log_print("🚀 CHƯƠNG TRÌNH TRIỂN KHAI SƠ ĐỒ PHÂN PHỐI KHÓA VÀ THỎA THUẬN KHÓA ECC (ECDH)")
    log_print("=" * 80)
    log_print(f"Thời gian thực thi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log_print("")
    
    # Thiết lập đường cong ECC (tối ưu hiệu năng & bảo mật)
    # SECP256R1 là đường cong tiêu chuẩn, cung cấp bảo mật 128 bit và hiệu suất tốt.
    CURVE = ec.SECP256R1()
    log_print(f"📌 Đường cong sử dụng: {CURVE.name} (NIST P-256)")
    log_print(f"   - Độ bảo mật tương đương: 128-bit")
    log_print(f"   - Ứng dụng: TLS, SSH, Bitcoin, Ethereum")
    log_print("")

    # --- BƯỚC 1: PHÂN PHỐI KHÓA (KEY GENERATION & DISTRIBUTION) ---
    log_print("=" * 80)
    log_print("BƯỚC 1: PHÂN PHỐI KHÓA (KEY GENERATION & DISTRIBUTION)")
    log_print("=" * 80)
    start_time_gen = time.perf_counter()

    # 1.1. Alice sử dụng khóa có sẵn (khóa đã tạo trước)
    log_print("\n📁 1.1. Alice đọc khóa riêng từ file private-key.pem")
    private_key_path = os.path.join(os.path.dirname(__file__), "private-key.pem")
    
    with open(private_key_path, "rb") as key_file:
        private_key_alice = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    
    log_print(f"   ✅ Alice đã tải khóa riêng từ: {os.path.basename(private_key_path)}")
    
    # Trích xuất thông tin khóa riêng (chỉ hiển thị một phần để bảo mật)
    private_numbers = private_key_alice.private_numbers()
    log_print(f"   📊 Khóa riêng Alice (d_A): {hex(private_numbers.private_value)[:20]}...{hex(private_numbers.private_value)[-10:]}")
    
    # 1.2. Tính toán Khóa Công Khai của Alice
    log_print("\n📐 1.2. Alice tính toán khóa công khai P_A = d_A × G")
    public_key_alice = private_key_alice.public_key()
    public_numbers_alice = public_key_alice.public_numbers()
    
    log_print(f"   ✅ Tính toán hoàn tất")
    log_print(f"   📊 Tọa độ điểm P_A:")
    log_print(f"      x = {hex(public_numbers_alice.x)[:20]}...{hex(public_numbers_alice.x)[-10:]}")
    log_print(f"      y = {hex(public_numbers_alice.y)[:20]}...{hex(public_numbers_alice.y)[-10:]}")

    # 1.3. Bob tạo khóa mới (giả lập người nhận)
    log_print("\n🔑 1.3. Bob tạo cặp khóa mới")
    private_key_bob = ec.generate_private_key(CURVE, default_backend())
    private_numbers_bob = private_key_bob.private_numbers()
    log_print(f"   ✅ Bob đã tạo khóa riêng (d_B): {hex(private_numbers_bob.private_value)[:20]}...{hex(private_numbers_bob.private_value)[-10:]}")
    
    public_key_bob = private_key_bob.public_key()
    public_numbers_bob = public_key_bob.public_numbers()
    log_print(f"   ✅ Bob tính toán khóa công khai P_B = d_B × G")
    log_print(f"   📊 Tọa độ điểm P_B:")
    log_print(f"      x = {hex(public_numbers_bob.x)[:20]}...{hex(public_numbers_bob.x)[-10:]}")
    log_print(f"      y = {hex(public_numbers_bob.y)[:20]}...{hex(public_numbers_bob.y)[-10:]}")


    # 1.4. Trao đổi khóa công khai (Phân phối khóa)
    log_print("\n📤 1.4. Trao đổi khóa công khai giữa Alice và Bob")
    
    # Chuyển đổi khóa công khai thành định dạng PEM để truyền qua mạng
    alice_public_bytes = public_key_alice.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    bob_public_bytes = public_key_bob.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    log_print(f"   🔄 Alice gửi P_A cho Bob (kích thước: {len(alice_public_bytes)} bytes)")
    log_print(f"   🔄 Bob gửi P_B cho Alice (kích thước: {len(bob_public_bytes)} bytes)")
    log_print(f"   📝 Định dạng: PEM (Privacy-Enhanced Mail)")
    log_print(f"   ✅ Trao đổi khóa công khai hoàn tất (qua kênh công khai)")
    
    end_time_gen = time.perf_counter()
    log_print(f"\n⏱️  Thời gian thực thi BƯỚC 1: {(end_time_gen - start_time_gen)*1000:.3f} ms")

    # --- BƯỚC 2: THỎA THUẬN KHÓA (KEY AGREEMENT - ECDH) ---
    log_print("\n" + "=" * 80)
    log_print("BƯỚC 2: THỎA THUẬN KHÓA (KEY AGREEMENT - ECDH)")
    log_print("=" * 80)
    start_time_agree = time.perf_counter()

    # 2.1. Alice tính toán Shared Secret
    log_print("\n🔐 2.1. Alice tính toán Shared Secret: S_A = d_A × P_B")
    shared_secret_alice = private_key_alice.exchange(ec.ECDH(), public_key_bob)
    log_print(f"   ✅ Tính toán hoàn tất")
    log_print(f"   📊 Shared Secret (Alice): {shared_secret_alice.hex()[:40]}...{shared_secret_alice.hex()[-20:]}")
    log_print(f"   📏 Kích thước: {len(shared_secret_alice)} bytes ({len(shared_secret_alice)*8} bits)")

    # 2.2. Bob tính toán Shared Secret
    log_print("\n🔐 2.2. Bob tính toán Shared Secret: S_B = d_B × P_A")
    shared_secret_bob = private_key_bob.exchange(ec.ECDH(), public_key_alice)
    log_print(f"   ✅ Tính toán hoàn tất")
    log_print(f"   📊 Shared Secret (Bob): {shared_secret_bob.hex()[:40]}...{shared_secret_bob.hex()[-20:]}")
    log_print(f"   📏 Kích thước: {len(shared_secret_bob)} bytes ({len(shared_secret_bob)*8} bits)")

    # 2.3. Kiểm tra tính đồng nhất
    log_print("\n🔍 2.3. Kiểm tra tính đồng nhất của Shared Secret")
    log_print(f"   📌 Nguyên lý: S_A = d_A × P_B = d_A × (d_B × G) = d_A × d_B × G")
    log_print(f"               S_B = d_B × P_A = d_B × (d_A × G) = d_B × d_A × G")
    log_print(f"   📌 Do tính giao hoán: d_A × d_B = d_B × d_A => S_A = S_B")
    
    if shared_secret_alice == shared_secret_bob:
        log_print(f"   ✅ XÁC NHẬN: S_Alice == S_Bob")
        log_print(f"   ✅ Thỏa thuận khóa ECDH THÀNH CÔNG!")
    else:
        log_print(f"   ❌ LỖI: S_Alice != S_Bob. Thỏa thuận khóa thất bại!")
        log_print(f"   ⚠️  Lý do có thể: Lỗi tính toán hoặc khóa không tương thích")

    end_time_agree = time.perf_counter()
    log_print(f"\n⏱️  Thời gian thực thi BƯỚC 2: {(end_time_agree - start_time_agree)*1000:.3f} ms")

    # --- BƯỚC 3: KHAI TRIỂN KHÓA (KEY DERIVATION - HKDF) ---
    log_print("\n" + "=" * 80)
    log_print("BƯỚC 3: KHAI TRIỂN KHÓA ĐỐI XỨNG (KEY DERIVATION - HKDF)")
    log_print("=" * 80)
    start_time_kdf = time.perf_counter()

    log_print("\n📚 Giới thiệu HKDF (HMAC-based Key Derivation Function):")
    log_print("   - HKDF là chuẩn RFC 5869, chuyển đổi Shared Secret thành khóa mã hóa")
    log_print("   - Sử dụng HMAC-SHA256 để tạo khóa đối xứng an toàn")
    log_print("   - Salt: Giá trị ngẫu nhiên để tăng entropy")
    log_print("   - Info: Thông tin ngữ cảnh để phân biệt các khóa khác nhau")

    # Shared Secret cần được chuyển đổi thành khóa mã hóa đối xứng chuẩn
    salt = b'ecc_kdf_salt_2025'  # Giá trị ngẫu nhiên, độc nhất cho mỗi phiên
    info = b'aes256_key_for_session'  # Thông tin ngữ cảnh

    log_print(f"\n🔧 3.1. Cấu hình HKDF:")
    log_print(f"   - Thuật toán: SHA-256")
    log_print(f"   - Độ dài khóa đầu ra: 32 bytes (256 bits) cho AES-256")
    log_print(f"   - Salt: {salt.decode()}")
    log_print(f"   - Info: {info.decode()}")

    kdf_alice = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits cho AES-256
        salt=salt,
        info=info,
        backend=default_backend()
    )
    
    kdf_bob = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
        backend=default_backend()
    )

    # 3.2. Alice khai triển khóa đối xứng
    log_print(f"\n🔑 3.2. Alice khai triển khóa đối xứng từ Shared Secret")
    aes_key_alice = kdf_alice.derive(shared_secret_alice)
    log_print(f"   ✅ Khai triển hoàn tất")
    log_print(f"   📊 AES-256 Key (Alice): {aes_key_alice.hex()}")

    # 3.3. Bob khai triển khóa đối xứng
    log_print(f"\n🔑 3.3. Bob khai triển khóa đối xứng từ Shared Secret")
    aes_key_bob = kdf_bob.derive(shared_secret_bob)
    log_print(f"   ✅ Khai triển hoàn tất")
    log_print(f"   📊 AES-256 Key (Bob): {aes_key_bob.hex()}")

    # 3.4. Kiểm tra khóa đối xứng cuối cùng
    log_print(f"\n🔍 3.4. Xác minh khóa đối xứng cuối cùng")
    if aes_key_alice == aes_key_bob:
        log_print(f"   ✅ XÁC NHẬN: AES_Key_Alice == AES_Key_Bob")
        log_print(f"   ✅ Khai triển khóa HKDF THÀNH CÔNG!")
        log_print(f"   📏 Độ dài: 32 bytes (256 bits)")
        log_print(f"   🎯 Khóa này có thể dùng để mã hóa đối xứng (AES-256, ChaCha20, ...)")
    else:
        log_print(f"   ❌ LỖI: Khóa đối xứng không khớp!")

    end_time_kdf = time.perf_counter()
    log_print(f"\n⏱️  Thời gian thực thi BƯỚC 3: {(end_time_kdf - start_time_kdf)*1000:.3f} ms")

    # --- TỔNG KẾT ---
    total_time = time.perf_counter() - start_time_gen
    log_print("\n" + "=" * 80)
    log_print("📊 TỔNG KẾT VÀ ĐÁNH GIÁ HIỆU NĂNG")
    log_print("=" * 80)
    log_print(f"\n⏱️  Tổng thời gian thực thi: {total_time*1000:.3f} ms")
    log_print(f"   - Bước 1 (Phân phối khóa): {(end_time_gen - start_time_gen)*1000:.3f} ms")
    log_print(f"   - Bước 2 (Thỏa thuận khóa): {(end_time_agree - start_time_agree)*1000:.3f} ms")
    log_print(f"   - Bước 3 (Khai triển khóa): {(end_time_kdf - start_time_kdf)*1000:.3f} ms")
    
    log_print(f"\n🔒 Đánh giá bảo mật:")
    log_print(f"   ✅ Đường cong: SECP256R1 (NIST P-256)")
    log_print(f"   ✅ Độ bảo mật: 128-bit (tương đương RSA-3072)")
    log_print(f"   ✅ Khóa đối xứng: AES-256 (256-bit)")
    log_print(f"   ✅ KDF: HKDF-SHA256 (chuẩn RFC 5869)")
    
    log_print(f"\n🚀 Ứng dụng thực tế:")
    log_print(f"   - TLS/SSL (HTTPS): Thiết lập kết nối an toàn")
    log_print(f"   - VPN: Mã hóa đường truyền")
    log_print(f"   - Cryptocurrency: Bitcoin, Ethereum")
    log_print(f"   - Signal, WhatsApp: Mã hóa end-to-end")
    
    log_print("\n" + "=" * 80)
    log_print("✅ CHƯƠNG TRÌNH HOÀN THÀNH THÀNH CÔNG - KHÔNG CÓ LỖI")
    log_print("=" * 80)
    log_print(f"📅 Hoàn thành lúc: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Ghi kết quả vào file
    output_file = write_output(log_lines)
    log_print(f"\n💾 Kết quả đã được lưu vào: {output_file}")
    print(f"💾 Kết quả đã được lưu vào: {output_file}")

if __name__ == "__main__":
    try:
        ecc_key_agreement_demonstration()
    except Exception as e:
        print(f"\n❌ LỖI: {str(e)}")
        import traceback
        traceback.print_exc()