import numpy as np
from PIL import Image
import os
from datetime import datetime

# Hàm log ra Console và file
def log_message(message, output_file=None):
    """Ghi tin nhắn ra Console và file nếu cần"""
    print(message)
    if output_file:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write(message + '\n')

# Hàm chuyển đổi chuỗi bit thành chuỗi ký tự
def bit_string_to_text(bit_string):
    """Chuyển chuỗi bit thành văn bản UTF-8"""
    if not bit_string:
        return ""
    
    # Padding thêm 0 ở cuối để độ dài chia hết cho 8
    remainder = len(bit_string) % 8
    if remainder != 0:
        bit_string = bit_string + '0' * (8 - remainder)
    
    # Chuyển chuỗi bit thành bytes
    byte_array = bytearray()
    for i in range(0, len(bit_string), 8):
        byte = bit_string[i:i+8]
        try:
            byte_value = int(byte, 2)
            byte_array.append(byte_value)
        except ValueError:
            pass
    
    # Decode từ UTF-8
    try:
        return byte_array.decode('utf-8', errors='ignore')
    except Exception:
        return ""

# Hàm chuyển đổi tin nhắn thành chuỗi bit
def text_to_bit_string(secret_message):
    """Chuyển văn bản UTF-8 thành chuỗi bit, thêm Stop Flag"""
    # Encode tin nhắn thành UTF-8 bytes
    message_bytes = secret_message.encode('utf-8')
    
    # Chuyển từng byte thành chuỗi bit 8 bit
    bit_string = ''.join(format(byte, '08b') for byte in message_bytes)
    
    # Thêm "Stop Flag" (cờ dừng) để biết khi nào kết thúc tin nhắn
    # Sử dụng chuỗi bit 16 ký tự '1111111100000000' làm Stop Flag (255 + 0 trong 1 byte)
    stop_flag = '1111111100000000'
    return bit_string + stop_flag

def hide_message(image_path, secret_message, output_path, log_file=None):
    """
    Ẩn tin nhắn vào ảnh sử dụng kỹ thuật LSB (Least Significant Bit)
    """
    log_message("\n" + "="*70, log_file)
    log_message("BƯỚC 1: TRIỂN KHAI ẨN TIN (ENCODING) - LSB STEGANOGRAPHY", log_file)
    log_message("="*70, log_file)
    
    try:
        # Kiểm tra file ảnh tồn tại
        if not os.path.exists(image_path):
            log_message(f"❌ LỖI: Không tìm thấy file ảnh: {image_path}", log_file)
            return False
            
        img = Image.open(image_path).convert('RGB')
        width, height = img.size
        
        # Chuyển ảnh sang mảng numpy để thao tác pixel hiệu năng cao
        data = np.array(img, dtype=np.uint8)
        
        # 1. Chuyển tin nhắn thành chuỗi bit
        bit_message = text_to_bit_string(secret_message)
        total_bits = len(bit_message)
        
        log_message(f"\n[BƯỚC 1.1] THÔNG TIN ẢNH GỐC:", log_file)
        log_message(f"  • Đường dẫn: {image_path}", log_file)
        log_message(f"  • Kích thước: {width} × {height} = {width * height} pixels", log_file)
        log_message(f"  • Dung lượng (RGB): {width * height * 3} bits", log_file)
        
        log_message(f"\n[BƯỚC 1.2] THÔNG TIN TIN NHẮN:", log_file)
        log_message(f"  • Tin nhắn gốc: '{secret_message}'", log_file)
        
        # Tính độ dài UTF-8
        message_bytes = secret_message.encode('utf-8')
        bytes_length = len(message_bytes)
        
        log_message(f"  • Độ dài ký tự: {len(secret_message)} ký tự", log_file)
        log_message(f"  • Độ dài bytes (UTF-8): {bytes_length} bytes", log_file)
        log_message(f"  • Chuỗi bit (kèm Stop Flag): {total_bits} bits", log_file)
        log_message(f"  • Stop Flag: '1111111100000000' (16 bits)", log_file)

        # 2. Kiểm tra dung lượng
        max_bits = width * height * 3  # R, G, B
        log_message(f"\n[BƯỚC 1.3] KIỂM TRA DUNG LƯỢNG:", log_file)
        log_message(f"  • Dung lượng cần: {total_bits} bits", log_file)
        log_message(f"  • Dung lượng tối đa: {max_bits} bits", log_file)
        
        if total_bits > max_bits:
            log_message(f"  • Tỉ lệ: {(total_bits/max_bits)*100:.2f}%", log_file)
            log_message(f"❌ LỖI: Tin nhắn quá lớn! Cần {total_bits} bits nhưng chỉ có {max_bits} bits.", log_file)
            return False
        else:
            log_message(f"  • Tỉ lệ: {(total_bits/max_bits)*100:.2f}% ✓ CÓ ĐỦ DUNG LƯỢNG", log_file)

        log_message(f"\n[BƯỚC 1.4] TRIỂN KHAI ẨN TIN (LSB EMBEDDING)...", log_file)
        bit_index = 0
        
        # Vòng lặp tối ưu: duyệt qua mảng numpy
        for row in range(height):
            for col in range(width):
                # data[row, col] là mảng [R, G, B]
                pixel = data[row, col]
                
                # 3. Thay thế LSB của từng kênh R, G, B
                for channel_index in range(3): # 0=R, 1=G, 2=B
                    if bit_index < total_bits:
                        current_bit = int(bit_message[bit_index])
                        # Thay thế LSB: (pixel[channel_index] & 254) xóa LSB, | current_bit gán bit mới
                        # 254 = 0xFE = 11111110 (xóa bit LSB)
                        data[row, col, channel_index] = np.uint8((pixel[channel_index] & 254) | current_bit)
                        bit_index += 1
                    else:
                        break 
                if bit_index >= total_bits:
                    break
            if bit_index >= total_bits:
                break
                
        log_message(f"  • Đã ẩn thành công {bit_index}/{total_bits} bits", log_file)
        
        # 4. Lưu ảnh đã ẩn tin
        log_message(f"\n[BƯỚC 1.5] LƯU ẢNH ĐÃ ẨN TIN:", log_file)
        stego_img = Image.fromarray(data)
        stego_img.save(output_path)
        
        file_size = os.path.getsize(output_path)
        log_message(f"  • Đường dẫn: {output_path}", log_file)
        log_message(f"  • Kích thước file: {file_size} bytes", log_file)
        log_message(f"✅ THÀNH CÔNG: Đã ẩn tin vào ảnh!", log_file)
        
        return True

    except FileNotFoundError as e:
        log_message(f"❌ LỖI: File không tìm thấy - {e}", log_file)
        return False
    except Exception as e:
        log_message(f"❌ LỖI không xác định: {type(e).__name__} - {e}", log_file)
        return False

def retrieve_message(stego_image_path, output_file, log_file=None):
    """
    Trích xuất tin nhắn từ ảnh sử dụng kỹ thuật LSB
    """
    log_message("\n" + "="*70, log_file)
    log_message("BƯỚC 2: TRIỂN KHAI DẤU TIN (DECODING) - LSB EXTRACTION", log_file)
    log_message("="*70, log_file)

    try:
        # Kiểm tra file ảnh tồn tại
        if not os.path.exists(stego_image_path):
            log_message(f"❌ LỖI: Không tìm thấy file ảnh: {stego_image_path}", log_file)
            return False
            
        img = Image.open(stego_image_path).convert('RGB')
        data = np.array(img, dtype=np.uint8)
        
        log_message(f"\n[BƯỚC 2.1] THÔNG TIN ẢNH ĐÃ ẨN TIN:", log_file)
        log_message(f"  • Đường dẫn: {stego_image_path}", log_file)
        log_message(f"  • Kích thước: {data.shape[1]} × {data.shape[0]} = {data.shape[0] * data.shape[1]} pixels", log_file)
        log_message(f"  • Dung lượng (RGB): {data.shape[0] * data.shape[1] * 3} bits", log_file)
        
        log_message(f"\n[BƯỚC 2.2] TRÍCH XUẤT TIN (LSB EXTRACTION)...", log_file)

        extracted_bits = []
        stop_flag = '1111111100000000' # Cờ dừng 16 bits
        found_flag = False
        
        # Vòng lặp tối ưu: duyệt qua mảng numpy
        for row in range(data.shape[0]):
            for col in range(data.shape[1]):
                pixel = data[row, col]
                
                # 1. Trích xuất LSB của từng kênh R, G, B
                for channel_index in range(3):
                    # Lấy LSB: pixel & 1
                    bit = str(pixel[channel_index] & 1)
                    extracted_bits.append(bit)
                    
                    # 2. Kiểm tra Cờ Dừng (Stop Flag)
                    if len(extracted_bits) >= 16:
                        current_bit_string = "".join(extracted_bits)
                        if current_bit_string[-16:] == stop_flag:
                            # Loại bỏ Stop Flag khỏi chuỗi bit
                            secret_bit_string = current_bit_string[:-16]
                            found_flag = True
                            break
                if found_flag:
                    break
            if found_flag:
                break
        
        if not found_flag:
            log_message(f"⚠️  CẢNH BÁO: Không tìm thấy Stop Flag!", log_file)
            log_message(f"  • Đã trích xuất {len(extracted_bits)} bits (có thể chưa hoàn chỉnh)", log_file)
            secret_bit_string = "".join(extracted_bits)
        else:
            log_message(f"  • Stop Flag tìm thấy! Dừng trích xuất.", log_file)
            log_message(f"  • Tổng bits trích xuất (kèm Stop Flag): {len(extracted_bits)} bits", log_file)
            log_message(f"  • Bits tin nhắn: {len(secret_bit_string)} bits", log_file)
        
        log_message(f"\n[BƯỚC 2.3] CHUYỂN ĐỔI CỬ STRING → VĂN BẢN:", log_file)
        # 3. Chuyển đổi chuỗi bit thành văn bản
        secret_message = bit_string_to_text(secret_bit_string)
        
        log_message(f"  • Độ dài tin nhắn: {len(secret_message)} ký tự", log_file)
        log_message(f"  • Tin nhắn trích xuất: '{secret_message}'", log_file)
        
        log_message(f"\n[BƯỚC 2.4] LƯU KẾT QUẢ:", log_file)
        # 4. Ghi kết quả ra file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(secret_message)
            
        log_message(f"  • Đường dẫn: {output_file}", log_file)
        log_message(f"  • Kích thước file: {os.path.getsize(output_file)} bytes", log_file)
        log_message(f"✅ THÀNH CÔNG: Đã trích xuất tin nhắn!", log_file)
        
        return True
        
    except FileNotFoundError as e:
        log_message(f"❌ LỖI: File không tìm thấy - {e}", log_file)
        return False
    except Exception as e:
        log_message(f"❌ LỖI không xác định: {type(e).__name__} - {e}", log_file)
        return False

def create_sample_image(output_path, width=800, height=600):
    """
    Tạo ảnh mẫu nếu chưa có ảnh gốc
    """
    try:
        # Tạo ảnh gradient đa màu (có nhiều pixel data để ẩn tin)
        img_array = np.zeros((height, width, 3), dtype=np.uint8)
        
        for row in range(height):
            for col in range(width):
                # Tạo gradient màu từ góc trái trên
                r = int(255 * col / width)
                g = int(255 * row / height)
                b = int(128 + 127 * (col + row) / (width + height))
                img_array[row, col] = [r, g, b]
        
        img = Image.fromarray(img_array)
        img.save(output_path)
        print(f"✓ Tạo ảnh mẫu: {output_path} ({width}x{height})")
        return True
    except Exception as e:
        print(f"❌ Lỗi tạo ảnh: {e}")
        return False

def main():
    """
    Chương trình chính: Ẩn tin và dấu tin
    """
    # --- CẤU HÌNH ĐƯỜNG DẪN ---
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    OUTPUT_DIR = os.path.join(os.path.dirname(BASE_DIR), "ket_qua")
    
    IMAGE_INPUT = os.path.join(BASE_DIR, "anh_goc.png")
    SECRET_TEXT = "Chương trình mã hóa này được viết bởi chuyên viên Crypto. Hiệu năng được tối ưu bằng Numpy. Tuyệt mật!"
    
    STEGO_OUTPUT = os.path.join(OUTPUT_DIR, "anh_da_ma_hoa.png")
    LOG_FILE = os.path.join(OUTPUT_DIR, "log_trinh_bay.txt")
    DECODED_OUTPUT = os.path.join(OUTPUT_DIR, "tin_giai_ma.txt")

    # Tạo thư mục kết quả nếu chưa có
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        print(f"✓ Tạo thư mục: {OUTPUT_DIR}")

    # Xóa log file cũ
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

    # Print header
    print("\n" + "="*70)
    print("CHƯƠNG TRÌNH ẨN TIN VÀ DẤU TIN (STEGANOGRAPHY)")
    print("Kỹ thuật: Least Significant Bit (LSB) Embedding")
    print("Tối ưu: NumPy arrays, uint8 datatype")
    print("="*70)
    
    log_message(f"\n{'='*70}", LOG_FILE)
    log_message(f"CHƯƠNG TRÌNH ẨN TIN VÀ DẤU TIN (STEGANOGRAPHY)", LOG_FILE)
    log_message(f"Kỹ thuật: Least Significant Bit (LSB) Embedding", LOG_FILE)
    log_message(f"{'='*70}", LOG_FILE)
    log_message(f"Thời gian chạy: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", LOG_FILE)
    log_message(f"Thư mục làm việc: {BASE_DIR}", LOG_FILE)

    # Kiểm tra/Tạo ảnh gốc
    print(f"\n[CHUẨN BỊ] Kiểm tra ảnh gốc...")
    if not os.path.exists(IMAGE_INPUT):
        print(f"⚠️  Ảnh gốc không tìm thấy! Tạo ảnh mẫu...")
        if create_sample_image(IMAGE_INPUT):
            log_message(f"\n[CHUẨN BỊ] Đã tạo ảnh mẫu: {IMAGE_INPUT}", LOG_FILE)
        else:
            log_message(f"❌ Không thể tạo ảnh mẫu!", LOG_FILE)
            return
    else:
        print(f"✓ Ảnh gốc tìm thấy: {IMAGE_INPUT}")
        log_message(f"\n[CHUẨN BỊ] Ảnh gốc: {IMAGE_INPUT}", LOG_FILE)

    # 1. TRIỂN KHAI ẨN TIN
    print(f"\n[BƯỚC 1] TRIỂN KHAI ẨN TIN...")
    success_encode = hide_message(IMAGE_INPUT, SECRET_TEXT, STEGO_OUTPUT, LOG_FILE)
    
    if not success_encode:
        log_message(f"\n❌ CHƯƠNG TRÌNH DỪNG: Lỗi trong quá trình ẩn tin", LOG_FILE)
        print("\n❌ CHƯƠNG TRÌNH DỪNG: Lỗi trong quá trình ẩn tin")
        return

    # 2. TRIỂN KHAI DẤU TIN
    print(f"\n[BƯỚC 2] TRIỂN KHAI DẤU TIN...")
    success_decode = retrieve_message(STEGO_OUTPUT, DECODED_OUTPUT, LOG_FILE)
    
    if not success_decode:
        log_message(f"\n❌ CHƯƠNG TRÌNH DỪNG: Lỗi trong quá trình dấu tin", LOG_FILE)
        print("\n❌ CHƯƠNG TRÌNH DỪNG: Lỗi trong quá trình dấu tin")
        return
    
    # 3. KẾT QUẢ CUỐI CÙNG
    print(f"\n" + "="*70)
    print(f"✅ HOÀN THÀNH THÀNH CÔNG!")
    print(f"="*70)
    print(f"\n📁 CÁC FILE KẾT QUẢ:")
    print(f"  • Ảnh ẩn tin: {STEGO_OUTPUT}")
    print(f"  • Tin giai mã: {DECODED_OUTPUT}")
    print(f"  • Log chi tiết: {LOG_FILE}")
    
    log_message(f"\n{'='*70}", LOG_FILE)
    log_message(f"✅ HOÀN THÀNH THÀNH CÔNG!", LOG_FILE)
    log_message(f"{'='*70}", LOG_FILE)
    log_message(f"\nThời gian kết thúc: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", LOG_FILE)
    log_message(f"\n📁 CÁC FILE KẾT QUẢ:", LOG_FILE)
    log_message(f"  • Ảnh ẩn tin: {STEGO_OUTPUT}", LOG_FILE)
    log_message(f"  • Tin giai mã: {DECODED_OUTPUT}", LOG_FILE)
    log_message(f"  • Log chi tiết: {LOG_FILE}", LOG_FILE)

if __name__ == "__main__":
    main()