# Ví dụ Crypto bằng Python — Windows (cmd.exe)

Bộ sưu tập các script ví dụ về mật mã sử dụng PyCryptodome và một số thư viện liên quan.

Yêu cầu Python
- Khuyến nghị dùng Python 3.8 trở lên

Cài đặt nhanh
1. (Tùy chọn) tạo môi trường ảo (virtual environment) trong thư mục dự án:

    python -m venv .venv

2. Kích hoạt môi trường ảo

    :: cmd.exe
    .venv\\Scripts\\activate

    :: PowerShell
    .venv\\Scripts\\Activate.ps1

3. Nâng cấp pip và cài đặt các phụ thuộc

    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt

Chạy các ví dụ
- Chạy ví dụ nhỏ `hello.py`:

    .venv\\Scripts\\python.exe hello.py

- Chạy ví dụ ECGDSA (tạo khóa, ký và xác minh thông điệp):

    .venv\\Scripts\\python.exe so_do_chu_ky_ECGDSA.py

- Tạo khóa RSA bằng thư viện `rsa` (nếu bạn có script gọi `rsa.newkeys`):

    .venv\\Scripts\\python.exe rsa_generate_keys.py

Khắc phục sự cố (Troubleshooting)
- Trùng tên module cục bộ: Nếu bạn có tệp `rsa.py` trong thư mục này, Python có thể import tệp đó thay vì package `rsa` cài bằng pip. Điều này gây ra lỗi như "module 'rsa' has no attribute 'newkeys'". Cách sửa:

    1. Đổi tên tệp cục bộ (ví dụ `rsa_generate_keys.py`).
    2. Xoá cache bytecode cũ nếu có:

       del rsa.pyc
       rmdir /s /q __pycache__

- Lỗi đường cong ECGDSA: Nếu bạn thấy lỗi "'str' object has no attribute 'order'" khi chạy `so_do_chu_ky_ECGDSA.py`, đó là do PyCryptodome biểu diễn `EccKey.curve` là tên chuỗi (tên đường cong). Cách sửa là tra thông số đường cong từ `Crypto.PublicKey.ECC._curves` để lấy bậc (order) `n` và điểm sinh (generator) `G`. Cách làm chung:

```python
# ví dụ ý tưởng:
from Crypto.PublicKey import ECC
from Crypto.Util import number

priv, pub = ECC.generate(curve='P-256'), None
curve_name = priv.curve
curve_params = ECC._curves[curve_name]
n = int(getattr(curve_params, 'order', None) or curve_params.get('n'))
# xây dựng G hoặc tạo ECC.EccPoint từ toạ độ nếu cần
```

Cập nhật `requirements.txt`
- Nếu bạn cài thêm gói trong khi venv đang bật, hãy cập nhật `requirements.txt`:

    python -m pip install <ten-goi>
    python -m pip freeze > requirements.txt

Ghi chú khác
- Kho này chỉ chứa các script ví dụ. Đọc kỹ và kiểm thử trước khi dùng vào môi trường sản xuất.

Bạn muốn mình:
- Ghi đè `README.md` bằng bản dịch tiếng Việt này, hoặc
- Giữ cả hai file (`README.md` và `README_VI.md`) và mình sẽ thêm 1 script ví dụ để tạo khóa RSA hợp lệ (ví dụ `rsa_generate_keys.py`)?
