import json
import base64
from pathlib import Path

def load_pem_json(path: Path):
    text = path.read_text(encoding="utf-8")
    # Lấy phần base64 giữa header/footer
    start = text.find("-----BEGIN")
    if start == -1:
        raise ValueError("Không tìm thấy BEGIN header trong " + str(path))
    # tìm dòng kết thúc header
    first_newline = text.find("\n", start)
    footer = "-----END"
    end = text.rfind(footer)
    if end == -1:
        raise ValueError("Không tìm thấy END footer trong " + str(path))
    b64 = text[first_newline+1:end].strip().replace("\n", "")
    decoded = base64.b64decode(b64).decode("utf-8")
    data = json.loads(decoded)
    # Chuyển các giá trị chuỗi số sang int nếu có thể
    for k, v in list(data.items()):
        try:
            data[k] = int(v)
        except Exception:
            data[k] = v
    return data

if __name__ == "__main__":
    base_dir = Path(__file__).parent
    pub_path = base_dir / "public-key.pem"
    priv_path = base_dir / "private-key.pem"

    if pub_path.exists():
        pub = load_pem_json(pub_path)
        print("Public key components:")
        print(json.dumps(pub, indent=2, ensure_ascii=False))
    else:
        print("Không tìm thấy:", pub_path)

    if priv_path.exists():
        priv = load_pem_json(priv_path)
        print("\nPrivate key components:")
        print(json.dumps(priv, indent=2, ensure_ascii=False))
    else:
        print("Không tìm thấy:", priv_path)
# ...existing code...