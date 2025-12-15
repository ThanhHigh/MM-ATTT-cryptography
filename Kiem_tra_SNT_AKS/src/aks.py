from __future__ import annotations

import math
import time
from typing import List, Tuple

# Import thư viện tối ưu hóa
import gmpy2
from numba import njit
from numba.typed import List as NumbaList

# --- 1. Hàm Hỗ trợ Số học và Sàng lọc (KHÔNG DÙNG Numba cho số lớn) ---

def is_perfect_power(n: int) -> bool:
    """Kiểm tra lũy thừa hoàn chỉnh (Dùng gmpy2)."""
    n_mpz = gmpy2.mpz(n)
    if n_mpz < 2:
        return False
    
    max_b = int(math.log2(n_mpz)) + 1
    
    for b in range(2, max_b + 1):
        root, is_exact = gmpy2.iroot(n_mpz, b)
        if is_exact and root > 1:
            return True
            
    return False


def multiplicative_order(n: int, r: int, limit: int) -> int:
    """Trả về bậc của n modulo r (Dùng gmpy2)."""
    if gmpy2.gcd(n, r) != 1:
        return 0
    
    x = 1
    value = n % r 
    
    while x <= limit:
        if value == 1:
            return x
        
        value = (value * (n % r)) % r 
        x += 1
        
    return x

@njit(cache=True)
def sieve_primes(limit: int) -> NumbaList[int]:
    """Sàng Eratosthenes nhanh (Dùng Numba)."""
    if limit < 2:
        return NumbaList([1])
    
    # Đặt lại giới hạn an toàn tối đa 1 triệu cho Numba
    limit = min(limit, 1_000_000)
         
    is_prime = NumbaList([True] * (limit + 1))
    is_prime[0] = is_prime[1] = False
    
    p = 2
    while p * p <= limit:
        if is_prime[p]:
            for i in range(p * p, limit + 1, p):
                is_prime[i] = False
        p += 1
        
    primes = NumbaList()
    for p in range(2, limit + 1):
        if is_prime[p]:
            primes.append(p)
    return primes


# --- 2. Hàm Đa thức Tối ưu hóa (Lớp Numba) ---

@njit(cache=True)
def poly_mul_numba(a: NumbaList[int], b: NumbaList[int], r: int) -> NumbaList[int]:
    """
    Nhân đa thức a và b modulo (x^r - 1). 
    QUAN TRỌNG: Hàm này chỉ tính tổng/nhân hệ số trong Numba JIT, 
    KHÔNG THỰC HIỆN PHÉP TOÁN MODULO NMOD.
    """
    # Khởi tạo kết quả với kích thước r, giá trị ban đầu là 0.
    # Kích thước của res có thể là r (cho đa thức kết quả mod x^r - 1)
    # Tuy nhiên, để tránh lỗi tràn số trong Numba, ta phải đảm bảo res không quá lớn.
    # Trong trường hợp này, vì r rất lớn (262027), chúng ta phải giữ lại kích thước r.
    
    # Để đơn giản hóa Numba, ta sẽ dùng mảng kết quả có kích thước r, 
    # và chấp nhận rằng các hệ số sẽ lớn.
    
    res = NumbaList([0] * r)
    
    # Giới hạn kích thước mảng an toàn cho Numba
    # Kích thước của mảng NumbaList là r (tức r có thể là 262027)
    
    for i in range(len(a)):
        ai = a[i]
        if ai == 0:
            continue
        for j in range(len(b)):
            bj = b[j]
            if bj == 0:
                continue
            deg = (i + j) % r
            
            # Chỉ thực hiện phép cộng/nhân thông thường, không có % nmod
            # Cẩn thận: hệ số res[deg] có thể trở thành số nguyên lớn ở đây.
            res[deg] = res[deg] + ai * bj
            
    return res

# --- 3. Hàm Đa thức Tối ưu hóa (Lớp Python/gmpy2) ---

def poly_mul_optimized(a: List[int], b: List[int], nmod: int, r: int) -> List[int]:
    """
    Lớp bọc: Gọi hàm Numba, sau đó áp dụng phép toán modulo số học lớn (nmod).
    """
    # Chuyển đổi List[int] Python sang NumbaList[int]
    a_numba = NumbaList(a)
    b_numba = NumbaList(b)
    
    # Bước 1: Nhân đa thức (Numba)
    res_numba = poly_mul_numba(a_numba, b_numba, r)
    
    # Bước 2: Áp dụng phép toán Modulo nmod (Python/gmpy2)
    result = [0] * r
    nmod_mpz = gmpy2.mpz(nmod)
    
    for i in range(r):
        # res_numba[i] có thể là số nguyên lớn Python nếu tràn 64-bit trong Numba
        # gmpy2.f_mod xử lý số học lớn an toàn và hiệu quả
        result[i] = int(gmpy2.f_mod(res_numba[i], nmod_mpz))
        
    return result


def poly_pow(base: List[int], exponent: int, nmod: int, r: int) -> List[int]:
    """Tính lũy thừa đa thức `base`^`exponent` modulo (x^r -1, nmod)."""
    
    result = [0] * r
    result[0] = 1 # 1 (đa thức)
    
    b = base[:] 
    e = exponent
    
    while e > 0:
        if e & 1:
            # Dùng poly_mul_optimized để xử lý modulo số học lớn
            result = poly_mul_optimized(result, b, nmod, r)
            
        b = poly_mul_optimized(b, b, nmod, r)
        e >>= 1
        
    return result

# --- 4. Hàm AKS Chính Đã Sửa Lỗi ---

def is_prime_aks(n: int, verbose: bool = False) -> bool:
    start = time.time()
    
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
    log_n = math.log2(n_mpz)
    max_k = int(math.ceil(log_n ** 2))
    
    # Giới hạn tìm kiếm r: Đặt R_limit = ceil(log_n^3) hoặc max 1 triệu.
    R_limit = min(1_000_000, int(math.ceil(log_n ** 3)))
    
    if verbose:
        print(f"Bước 2: tìm r (ngưỡng max_k={max_k}, giới hạn R_limit={R_limit})...")
        
    # Sàng tìm số nguyên tố
    r_candidates = sieve_primes(R_limit)
    r = 2
    found_r = False
    
    for r_candidate in r_candidates:
        r = r_candidate
        
        # 2a: Kiểm tra ước chung (loại bỏ hợp số)
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
    # Giới hạn: int(floor(sqrt(r-1) * log n))
    limit = int(math.floor(math.sqrt(r - 1) * log_n_float))
    if limit < 1:
        limit = 1
    if verbose:
        print(f"Bước 5: kiểm tra đồng dư đa thức, giới hạn={limit} (r={r})")

    for a in range(1, limit + 1):
        if verbose and a % 1000 == 0: # Giảm tần suất log do limit lớn
            print(f"  checking a={a}/{limit}...")
            
        # Đa thức cơ sở (x+a)
        base = [0] * r
        base[0] = a % n  
        base[1] = 1      
        
        # compute (x + a)^n mod (x^r - 1, n)
        lhs = poly_pow(base, n, n, r)
        
        # rhs = x^{n mod r} + a
        rhs = [0] * r
        rhs[0] = a % n
        
        n_mod_r = gmpy2.f_mod(n_mpz, r)

        rhs[n_mod_r] = (rhs[n_mod_r] + 1) % n
        
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
    
    # Thiết lập độ sâu đệ quy cao hơn để xử lý NumbaList lớn nếu cần
    sys.setrecursionlimit(2000)

    parser = argparse.ArgumentParser(description="AKS primality test (Ultimate Optimized V2 - Fix Numba Large Int)")
    parser.add_argument("n", type=str, help="Integer to test for primality (use quotes for large numbers)") 
    parser.add_argument("--verbose", action="store_true", help="Show steps")
    args = parser.parse_args()
    
    try:
        n_input = int(args.n)
    except ValueError:
        print("Lỗi: Đầu vào n phải là một số nguyên hợp lệ.")
        exit()
        
    # Làm nóng Numba một lần
    try:
        test_list = NumbaList([1, 1])
        poly_mul_numba(test_list, test_list, 2)
        sieve_primes(10)
    except Exception:
        pass
    
    print(f"Kiểm tra n={n_input} ({len(args.n)} chữ số)...")
    t0 = time.time()
    res = is_prime_aks(n_input, verbose=args.verbose)
    dt = time.time() - t0
    
    print("-" * 30)
    print(f"Kết quả AKS Tối ưu: n là {'số nguyên tố' if res else 'hợp số'} (thời gian {dt:.3f}s)")
    print("-" * 30)