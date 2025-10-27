# Hướng dẫn ngắn — Chạy ví dụ Crypto trên máy ảo Windows (cmd.exe)

Mục tiêu: thiết lập nhanh trong máy ảo Windows, cài & cập nhật phụ thuộc, và chạy ví dụ mẫu.

Yêu cầu
- Windows (trên máy ảo), Python 3.8+
- Quy ước: làm việc trong thư mục dự án chứa README.md và requirements.txt

1) Tạo và kích hoạt virtual environment
- Tạo venv:
```cmd
python -m venv .venv
```
- Kích hoạt (cmd.exe):
```cmd
.venv\Scripts\activate
```
- Hoặc PowerShell:
```powershell
.venv\Scripts\Activate.ps1
```

2) Cập nhật pip và cài phụ thuộc
```cmd
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

3) Chạy ví dụ (trong venv đã kích hoạt)
- Ví dụ đơn giản:
```cmd
.venv\Scripts\python.exe hello.py
```
- Ví dụ ký/kiểm tra ECDSA:
```cmd
.venv\Scripts\python.exe so_do_chu_ky_ECDSA.py
```

5) Cập nhật requirements.txt
- Sau khi cài thêm gói trong venv:
```cmd
python -m pip install <ten-goi>
python -m pip freeze > requirements.txt
```
