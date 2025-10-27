# Python Crypto examples — Windows (cmd.exe)

A small collection of cryptography example scripts using PyCryptodome and related libraries.

Minimum Python
- Python 3.8+ recommended

Quick setup
1. (Optional) create a virtual environment in the project folder:

    python -m venv .venv

2. Activate the venv

    :: cmd.exe
    .venv\Scripts\activate

    :: PowerShell
    .venv\Scripts\Activate.ps1

3. Upgrade pip and install dependencies

    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt

Running the examples
- Run the small hello example:

    .venv\Scripts\python.exe hello.py

- Run the ECGDSA example (creates keys, signs and verifies a message):

    .venv\Scripts\python.exe so_do_chu_ky_ECGDSA.py

- Key generation using the `rsa` library (if you have a script that calls `rsa.newkeys`):

    .venv\Scripts\python.exe rsa_generate_keys.py

Troubleshooting
- Local module shadowing: If you have a file named `rsa.py` in this folder, Python may import it instead of the external `rsa` package from `pip`. This causes errors like "module 'rsa' has no attribute 'newkeys'". Fix:

    1. Rename your local file (for example `rsa_generate_keys.py`).
    2. Remove stale bytecode cache:

       del rsa.pyc
       rmdir /s /q __pycache__

- ECGDSA curve errors: If you see "'str' object has no attribute 'order'" when running `so_do_chu_ky_ECGDSA.py`, that's because PyCryptodome represents `EccKey.curve` as a string (curve name). The fix is to look up curve parameters from `Crypto.PublicKey.ECC._curves` and read the curve order (n) and generator (G). A robust approach is:

```python
# example (concept):
from Crypto.PublicKey import ECC
from Crypto.Util import number

priv, pub = ECC.generate(curve='P-256'), None
curve_name = priv.curve
curve_params = ECC._curves[curve_name]
n = int(getattr(curve_params, 'order', None) or curve_params.get('n'))
# derive G or construct ECC.EccPoint from coordinates
```

Updating requirements
- If you install a new package while the venv is active, update `requirements.txt`:

    python -m pip install <package-name>
    python -m pip freeze > requirements.txt

Other notes
- This repository contains example scripts only. Review code before using in production.

If you'd like, I can add a small `generate_keys.py` to demonstrate correct RSA key generation (and avoid naming conflicts).
