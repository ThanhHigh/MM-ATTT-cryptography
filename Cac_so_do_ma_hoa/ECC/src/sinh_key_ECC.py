"""
Chương trình sinh cặp khóa ECC (Elliptic Curve Cryptography)
Curve: P-256 (NIST P-256 / secp256r1)
"""

from Crypto.PublicKey import ECC
import binascii

PUBLIC_FILE = "public-key.pem"
PRIVATE_FILE = "private-key.pem"

def print_section(title):
    """In tiêu đề phần"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)

if __name__ == "__main__":
    print("\n" + "█"*70)
    print("█" + " "*19 + "CHƯƠNG TRÌNH SINH KHÓA ECC" + " "*20 + "█")
    print("█"*70)
    
    print_section("SINH CẶP KHÓA ECC")
    
    print("\n[Bước 1] Tạo cặp khóa ECC với đường cong P-256")
    print("-" * 70)
    print("   > Đường cong: NIST P-256 (secp256r1)")
    print("   > Độ dài khóa: 256 bits")
    print("   > Đang sinh khóa...")
    
    # Sinh khóa
    key = ECC.generate(curve='P-256')
    
    print("   > ✓ Đã sinh khóa thành công!")
    
    print("\n[Bước 2] Thông tin khóa riêng")
    print("-" * 70)
    print(f"   > Khóa riêng (d): {hex(key.d)}")
    print(f"   > Độ dài: {key.d.bit_length()} bits")
    
    print("\n[Bước 3] Thông tin khóa công khai")
    print("-" * 70)
    print(f"   > Khóa công khai (x): {hex(key.pointQ.x)}")
    print(f"   > Khóa công khai (y): {hex(key.pointQ.y)}")
    print(f"   > Đường cong: {key.curve}")
    
    print("\n[Bước 4] Xuất khóa riêng ra file PEM")
    print("-" * 70)
    private_pem = key.export_key(format='PEM')
    with open(PRIVATE_FILE, "wt") as f:
        f.write(private_pem)
    print(f"   > ✓ Đã lưu khóa riêng vào: {PRIVATE_FILE}")
    print(f"   > Nội dung:")
    for line in private_pem.split('\n')[:3]:
        print(f"      {line}")
    print("      ...")
    
    print("\n[Bước 5] Xuất khóa công khai ra file PEM")
    print("-" * 70)
    public_key = key.public_key()
    public_pem = public_key.export_key(format='PEM')
    with open(PUBLIC_FILE, "wt") as f:
        f.write(public_pem)
    print(f"   > ✓ Đã lưu khóa công khai vào: {PUBLIC_FILE}")
    print(f"   > Nội dung:")
    for line in public_pem.split('\n')[:3]:
        print(f"      {line}")
    print("      ...")
    
    print_section("THÔNG TIN ĐƯỜNG CONG ECC P-256")
    print("\nĐường cong P-256 (secp256r1) là đường cong elliptic được NIST chuẩn hóa")
    print("Phương trình: y² = x³ + ax + b (mod p)")
    print("\nThông số:")
    print("  • p = 2^256 - 2^224 + 2^192 + 2^96 - 1")
    print("  • a = p - 3")
    print("  • b = 410583637251521421293261297800472684091144410159937")
    print("       88866493674564574956793863096954503103")
    print("  • Độ dài khóa: 256 bits")
    print("  • Bậc của nhóm điểm: ~2^256")
    
    print_section("AN TOÀN")
    print("\n⚠ LƯU Ý QUAN TRỌNG:")
    print("  • Khóa riêng phải được bảo mật tuyệt đối")
    print("  • Không chia sẻ khóa riêng với bất kỳ ai")
    print("  • Khóa công khai có thể chia sẻ công khai")
    print("  • Sử dụng khóa riêng để giải mã và ký")
    print("  • Sử dụng khóa công khai để mã hóa và xác thực chữ ký")
    
    # Ghi kết quả vào file
    print_section("LƯU KẾT QUẢ")
    output_file = "../ket_qua/ECC_keygen.txt"
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("="*70 + "\n")
            f.write("KẾT QUẢ SINH KHÓA ECC (P-256)\n")
            f.write("="*70 + "\n\n")
            
            f.write("1. THÔNG TIN KHÓA RIÊNG\n")
            f.write("-" * 70 + "\n")
            f.write(f"Khóa riêng (d): {hex(key.d)}\n")
            f.write(f"Độ dài: {key.d.bit_length()} bits\n")
            f.write(f"File: {PRIVATE_FILE}\n\n")
            
            f.write("2. THÔNG TIN KHÓA CÔNG KHAI\n")
            f.write("-" * 70 + "\n")
            f.write(f"Khóa công khai (x): {hex(key.pointQ.x)}\n")
            f.write(f"Khóa công khai (y): {hex(key.pointQ.y)}\n")
            f.write(f"Đường cong: {key.curve}\n")
            f.write(f"File: {PUBLIC_FILE}\n\n")
            
            f.write("3. ĐỊNH DẠNG PEM\n")
            f.write("-" * 70 + "\n")
            f.write("Khóa riêng (PEM):\n")
            f.write(private_pem + "\n\n")
            f.write("Khóa công khai (PEM):\n")
            f.write(public_pem + "\n\n")
            
            f.write("4. THÔNG TIN ĐƯỜNG CONG P-256\n")
            f.write("-" * 70 + "\n")
            f.write("Đường cong P-256 (secp256r1)\n")
            f.write("Phương trình: y² = x³ + ax + b (mod p)\n")
            f.write("Độ dài khóa: 256 bits\n")
            f.write("Mức độ an toàn: tương đương RSA-3072 bits\n\n")
            
            f.write("5. HƯỚNG DẪN SỬ DỤNG\n")
            f.write("-" * 70 + "\n")
            f.write("• Khóa riêng: dùng để giải mã và ký số\n")
            f.write("• Khóa công khai: dùng để mã hóa và xác thực chữ ký\n")
            f.write("• Bảo mật khóa riêng tuyệt đối\n")
            f.write("• Có thể chia sẻ khóa công khai công khai\n")
        
        print(f"✓ Đã lưu kết quả vào: {output_file}")
    except Exception as e:
        print(f"❌ Lỗi khi lưu file: {e}")
    
    print("\n" + "█"*70)
    print("█" + " "*22 + "HOÀN TẤT CHƯƠNG TRÌNH" + " "*21 + "█")
    print("█"*70 + "\n")
