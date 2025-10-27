# Mật mã và An toàn thông tin

## Nguyễn Đức Thành - 22021150
## Cài đặt hệ mật RSA, ElGamal, ECC và sơ đồ chữ ký ECDSA
## Số bit hiện tại 128

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
