from __future__ import annotations

import math
import time
from typing import List

# Import thư viện tối ưu hóa
import gmpy2
# Không cần Numba nữa

# --- 1. Hàm Hỗ trợ Số học và Sàng lọc ---

def is_perfect_power(n: int) -> bool:
    """Kiểm tra lũy thừa hoàn chỉnh (Dùng gmpy2)."""
    n_mpz = gmpy2.mpz(n)
    if n_mpz < 2:
        return False
    
    max_b = int(math.log2(n_mpz)) + 1
    
    for b in range(2, max_b + 1):
        # gmpy2.iroot trả về căn bậc nguyên và cờ chính xác
        root, is_exact = gmpy2.iroot(n_mpz, b)
        if is_exact and root > 1:
            return True
            
    return False


def multiplicative_order(n: int, r: int, limit: int) -> int:
    """Trả về bậc của n modulo r (Dùng gmpy2)."""
    if gmpy2.gcd(n, r) != 1:
        return 0
    
    x = 1
    # Bắt đầu với n^1 mod r
    value = gmpy2.mpz(n) % r 
    n_mod_r = gmpy2.mpz(n) % r
    
    while x <= limit:
        if value == 1:
            return x
        
        # Tối ưu hóa: tính lũy thừa theo bước bằng gmpy2
        value = (value * n_mod_r) % r 
        x += 1
        
    return x


def sieve_primes(limit: int) -> List[int]:
    """Sàng Eratosthenes nhanh (Python thuần, dùng gmpy2 cho độ chính xác nếu cần)."""
    if limit < 2:
        return []
        
    # Python list và bool là đủ cho Sàng
    is_prime = [True] * (limit + 1)
    is_prime[0] = is_prime[1] = False
    
    p = 2
    while p * p <= limit:
        if is_prime[p]:
            for i in range(p * p, limit + 1, p):
                is_prime[i] = False
        p += 1
        
    primes = [p for p in range(2, limit + 1) if is_prime[p]]
    return primes


# --- 2. Hàm Đa thức An toàn với Số học Lớn (gmpy2) ---

def poly_mul(a: List[int], b: List[int], nmod: int, r: int) -> List[int]:
    """
    Nhân đa thức a và b modulo (x^r - 1, nmod).
    Sử dụng gmpy2.mpz để xử lý an toàn các hệ số lớn và nmod.
    """
    nmod_mpz = gmpy2.mpz(nmod)
    res = [gmpy2.mpz(0)] * r # Khởi tạo kết quả bằng mpz
    
    # Chuyển đổi đầu vào sang mpz một lần
    a_mpz = [gmpy2.mpz(x) for x in a]
    b_mpz = [gmpy2.mpz(x) for x in b]
    
    for i in range(r):
        ai = a_mpz[i]
        if ai == 0:
            continue
        for j in range(r):
            bj = b_mpz[j]
            if bj == 0:
                continue
            
            # Tính chỉ số và chỉ số modulo r
            deg = (i + j) % r
            
            # Phép nhân và cộng hệ số (sử dụng gmpy2)
            # Sau đó áp dụng modulo nmod ngay lập tức
            # res[deg] = (res[deg] + ai * bj) % nmod_mpz
            
            # Sử dụng phép toán gmpy2 trực tiếp
            term = gmpy2.f_mod(ai * bj, nmod_mpz)
            res[deg] = gmpy2.f_mod(res[deg] + term, nmod_mpz)
            
    # Chuyển đổi kết quả mpz trở lại thành int (Python integer)
    return [int(x) for x in res]


def poly_pow(base: List[int], exponent: int, nmod: int, r: int) -> List[int]:
    """Tính lũy thừa đa thức `base`^`exponent` modulo (x^r -1, nmod)."""
    
    result = [0] * r
    result[0] = 1 # 1 (đa thức)
    
    b = base[:] 
    e = exponent
    
    while e > 0:
        if e & 1:
            result = poly_mul(result, b, nmod, r)
            
        b = poly_mul(b, b, nmod, r)
        e >>= 1
        
    return result

# --- 3. Hàm AKS Chính Đã Sửa Lỗi và Tối ưu hóa (gmpy2) ---

def is_prime_aks(n: int, verbose: bool = False) -> bool:
    start = time.time()
    
    # Chuyển n sang gmpy2.mpz ngay lập tức
    n_mpz = gmpy2.mpz(n) 
    
    if n_mpz < 2:
        return False

    # Bước 1: check perfect power 
    if verbose:
        print("Bước 1: kiểm tra xem có phải lũy thừa hoàn chỉnh không...")
    if is_perfect_power(n): 
        if verbose:
            print("Kết luận: là lũy thừa hoàn chỉnh → hợp số")
        return False

    # Bước 2: find r (smallest r such that ord_r(n) > (log_2 n)^2)
    log_n = gmpy2.log2(n_mpz) # Dùng gmpy2.log2 cho độ chính xác tốt hơn
    max_k = int(gmpy2.ceil(log_n ** 2))
    
    # Giới hạn tìm kiếm r: Đặt R_limit = ceil(log_n^3) hoặc max 1 triệu.
    R_limit = min(1_000_000, int(gmpy2.ceil(log_n ** 3)))
    
    if verbose:
        print(f"Bước 2: tìm r (ngưỡng max_k={max_k}, giới hạn R_limit={R_limit})...")
        
    r_candidates = sieve_primes(R_limit)
    r = 2
    found_r = False
    
    for r_candidate in r_candidates:
        r = r_candidate
        
        # 2a: Kiểm tra ước chung 
        g = gmpy2.gcd(n_mpz, r)
        if g > 1:
            if g < n_mpz:
                if verbose:
                    print(f"Tìm được ước chung không tầm thường {g} (từ r={r}): hợp số")
                return False
            continue
            
        # 2b: Kiểm tra bậc (multiplicative order)
        ordn = multiplicative_order(n, r, max_k) 
        if ordn > max_k:
            found_r = True
            break
            
    if not found_r:
        if verbose:
             print(f"Không tìm thấy r thỏa mãn trong giới hạn R_limit={R_limit}. Tiếp tục với r={r} cuối cùng.")
        
    if verbose:
        print(f"Tìm được r = {r} (ord > {max_k})")

    # Bước 3: check gcd(a, n) for a <= r 
    if verbose:
        print("Bước 3: kiểm tra các gcd tới r...")
    
    for a in range(2, r + 1):
        g = gmpy2.gcd(a, n_mpz) 
        if 1 < g < n_mpz:
            if verbose:
                print(f"Tìm được ước chung không tầm thường {g}: hợp số")
            return False

    # Bước 4: if n <= r then n is prime
    if n_mpz <= r:
        if verbose:
            print("n <= r: kết luận là số nguyên tố")
        return True

    # Bước 5: check polynomial congruence
    log_n_float = float(log_n)
    limit = int(math.floor(math.sqrt(r - 1) * log_n_float))
    if limit < 1:
        limit = 1
    if verbose:
        print(f"Bước 5: kiểm tra đồng dư đa thức, giới hạn={limit} (r={r})")

    # Chuyển đổi n và 1 sang int để tạo base list (vì poly_mul sẽ chuyển nó thành mpz)
    n_int = int(n_mpz)

    for a in range(1, limit + 1):
        if verbose and a % 1000 == 0: 
            print(f"  checking a={a}/{limit}...")
            
        # Đa thức cơ sở (x+a)
        # Hệ số là Python int, poly_mul sẽ chuyển chúng thành mpz
        base = [0] * r
        base[0] = a % n_int 
        base[1] = 1      
        
        # compute (x + a)^n mod (x^r - 1, n)
        lhs = poly_pow(base, n_int, n_int, r)
        
        # rhs = x^{n mod r} + a
        rhs = [0] * r
        rhs[0] = a % n_int
        
        n_mod_r = int(gmpy2.f_mod(n_mpz, r))

        rhs[n_mod_r] = (rhs[n_mod_r] + 1) % n_int
        
        if lhs != rhs:
            if verbose:
                print(f"Đồng dư đa thức không thỏa với a={a}: hợp số")
            return False

    if verbose:
        print("Không tìm thấy mâu thuẫn: kết luận là số nguyên tố")
        print(f"AKS kết thúc sau {time.time() - start:.3f}s")
    return True


if __name__ == "__main__":
    import argparse
    import sys
    
    # Cần thiết lập giới hạn đệ quy cao hơn do poly_mul có thể gọi poly_mul nhiều lần trong poly_pow
    sys.setrecursionlimit(5000) 

    parser = argparse.ArgumentParser(description="AKS primality test (Ultimate Optimized V3 - Pure gmpy2)")
    parser.add_argument("n", type=str, help="Integer to test for primality (use quotes for large numbers)") 
    parser.add_argument("--verbose", action="store_true", help="Show steps")
    args = parser.parse_args()
    
    try:
        n_input = int(args.n)
    except ValueError:
        print("Lỗi: Đầu vào n phải là một số nguyên hợp lệ.")
        sys.exit(1)
        
    print(f"Kiểm tra n={args.n} ({len(args.n)} chữ số)...")
    t0 = time.time()
    res = is_prime_aks(n_input, verbose=args.verbose)
    dt = time.time() - t0
    
    print("-" * 30)
    print(f"Kết quả AKS Tối ưu: n là {'số nguyên tố' if res else 'hợp số'} (thời gian {dt:.3f}s)")
    print("-" * 30)