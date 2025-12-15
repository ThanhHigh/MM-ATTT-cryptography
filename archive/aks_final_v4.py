from __future__ import annotations

import math
import time
import sys
from typing import List, Union

# Tăng giới hạn đệ quy để tránh lỗi RecursionError trong poly_pow
sys.setrecursionlimit(5000) 

# Import thư viện toán học số học lớn
import gmpy2

# --- CÁC HÀM HỖ TRỢ SỐ HỌC (Sử dụng gmpy2) ---

def is_perfect_power(n: int) -> bool:
    """Kiểm tra xem n có phải là lũy thừa hoàn chỉnh không (n = a^b, a, b > 1)."""
    n_mpz = gmpy2.mpz(n)
    if n_mpz < 2:
        return False
    
    # Tính max_b an toàn bằng gmpy2.log2
    max_b = int(gmpy2.log2(n_mpz)) + 1
    
    for b in range(2, max_b + 1):
        root, is_exact = gmpy2.iroot(n_mpz, b)
        if is_exact and root > 1:
            return True
            
    return False


def multiplicative_order(n: int, r: int, limit: int) -> int:
    """Trả về bậc của n modulo r."""
    if gmpy2.gcd(n, r) != 1:
        return 0
    
    x = 1
    n_mpz = gmpy2.mpz(n)
    value = n_mpz % r 
    n_mod_r = n_mpz % r
    
    while x <= limit:
        if value == 1:
            return x
        
        # Tối ưu hóa: tính lũy thừa theo bước
        value = (value * n_mod_r) % r 
        x += 1
        
    return x


def sieve_primes(limit: int) -> List[int]:
    """Sàng Eratosthenes để tạo danh sách số nguyên tố."""
    if limit < 2:
        return []
        
    # Python list và bool là đủ cho Sàng (limit max 1 triệu)
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


# --- HÀM ĐA THỨC (NÚT THẮT CỔ CHAI O(r^2) ĐƯỢC XỬ LÝ BẰNG gmpy2) ---

def poly_mul(a: List[Union[int, gmpy2.mpz]], b: List[Union[int, gmpy2.mpz]], nmod: int, r: int) -> List[int]:
    """
    Nhân đa thức a và b modulo (x^r - 1, nmod) O(r^2).
    Sử dụng gmpy2.mpz cho tất cả các hệ số để ngăn chặn OverflowError.
    """
    nmod_mpz = gmpy2.mpz(nmod)
    res = [gmpy2.mpz(0)] * r
    
    # Chuyển đổi đầu vào sang gmpy2.mpz (đảm bảo an toàn)
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
            
            deg = (i + j) % r
            
            # Tính (ai * bj) mod nmod
            term = gmpy2.f_mod(ai * bj, nmod_mpz)
            
            # Tính (res[deg] + term) mod nmod
            res[deg] = gmpy2.f_mod(res[deg] + term, nmod_mpz)
            
    # Chuyển đổi kết quả mpz trở lại thành int (Python integer)
    return [int(x) for x in res]


def poly_pow(base: List[Union[int, gmpy2.mpz]], exponent: int, nmod: int, r: int) -> List[int]:
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

# --- HÀM AKS CHÍNH ---

def is_prime_aks(n: int, verbose: bool = False, debug_limit: int = 0) -> bool:
    start = time.time()
    
    n_mpz = gmpy2.mpz(n) 
    
    if n_mpz < 2:
        return False

    if verbose:
        print("Bước 1: kiểm tra xem có phải lũy thừa hoàn chỉnh không...")
    if is_perfect_power(n): 
        if verbose:
            print("Kết luận: là lũy thừa hoàn chỉnh → hợp số")
        return False

    # Bước 2: Tìm r (sử dụng giới hạn an toàn để tránh lặp vô tận)
    log_n = gmpy2.log2(n_mpz)
    max_k = int(gmpy2.ceil(log_n ** 2))
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

    # Bước 3: check gcd(a, n) for a <= r (kiểm tra lại cho các số còn lại)
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
        
    # Áp dụng giới hạn debug nếu được cung cấp (chỉ để kiểm tra logic)
    if debug_limit > 0 and debug_limit < limit:
        limit = debug_limit
        if verbose:
            print(f"!!! Cảnh báo: Giới hạn L đã bị giảm xuống {limit} (DEBUG MODE) !!!")

    if verbose:
        print(f"Bước 5: kiểm tra đồng dư đa thức, giới hạn={limit} (r={r})")

    # n_int là số mũ và modulus cho phép toán đa thức
    n_int = int(n_mpz)

    for a in range(1, limit + 1):
        if verbose and a % 1000 == 0: 
            print(f"  checking a={a}/{limit}...")
            
        # Đa thức cơ sở (x+a)
        base = [0] * r
        base[0] = a % n_int 
        base[1] = 1      
        
        # Vế trái (LHS): (x + a)^n mod (x^r - 1, n)
        lhs = poly_pow(base, n_int, n_int, r)
        
        # Vế phải (RHS): x^{n mod r} + a
        rhs = [0] * r
        rhs[0] = a % n_int
        
        n_mod_r = int(gmpy2.f_mod(n_mpz, r))

        rhs[n_mod_r] = (rhs[n_mod_r] + 1) % n_int
        
        # So sánh hệ số
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
    
    parser = argparse.ArgumentParser(description="AKS primality test (V4 - Optimized gmpy2, O(r^2))")
    parser.add_argument("n", type=str, help="Integer to test for primality (use quotes for large numbers)") 
    parser.add_argument("--verbose", action="store_true", help="Show steps")
    parser.add_argument("--debug-limit", type=int, default=0, 
                        help="Tùy chọn: Giảm giới hạn L của bước 5 (vd: 5) để kiểm tra logic nhanh.")
    args = parser.parse_args()
    
    try:
        n_input = int(args.n)
    except ValueError:
        print("Lỗi: Đầu vào n phải là một số nguyên hợp lệ.")
        sys.exit(1)
        
    print(f"Kiểm tra n={args.n} ({len(args.n)} chữ số)...")
    t0 = time.time()
    
    # Truyền debug_limit vào hàm
    res = is_prime_aks(n_input, verbose=args.verbose, debug_limit=args.debug_limit)
    
    dt = time.time() - t0
    
    print("-" * 30)
    print(f"Kết quả AKS: n là {'số nguyên tố' if res else 'hợp số'} (thời gian {dt:.3f}s)")
    print("-" * 30)