from __future__ import annotations

import math
import time
from typing import List

# Import thư viện tối ưu hóa
import gmpy2
from numba import njit
from numba.typed import List as NumbaList

# --- 1. Hàm Hỗ trợ Số học và Sàng lọc ---

def is_perfect_power(n: int) -> bool:
    """Kiểm tra xem n có phải là lũy thừa hoàn chỉnh không (n = a^b, a, b > 1).
    Sử dụng gmpy2.iroot cho số học lớn an toàn."""
    
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
    """Trả về bậc của n modulo r, nếu > limit thì trả về > limit.
    Sử dụng gmpy2.gcd."""
    
    if gmpy2.gcd(n, r) != 1:
        return 0
    
    x = 1
    value = n % r 
    
    while x <= limit:
        if value == 1:
            return x
        
        # Tối ưu hóa: tính lũy thừa theo bước
        value = (value * (n % r)) % r 
        x += 1
        
    return x # > limit

@njit(cache=True)
def sieve_primes(limit: int) -> NumbaList[int]:
    """Sàng Eratosthenes nhanh để tạo danh sách số nguyên tố đến limit. (Dùng Numba)"""
    if limit < 2:
        return NumbaList([1])
        
    # Giới hạn mảng tối đa 1 triệu để tránh lỗi bộ nhớ Numba
    if limit > 1_000_000:
         limit = 1_000_000
         
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


# --- 2. Hàm Đa thức Tối ưu hóa (Sử dụng Numba) ---

@njit(cache=True)
def poly_mul(a: NumbaList[int], b: NumbaList[int], nmod: int, r: int) -> NumbaList[int]:
    """Nhân đa thức a và b modulo (x^r - 1, nmod). (Dùng Numba JIT)"""
    res = NumbaList([0] * r)
    
    for i in range(len(a)):
        ai = a[i]
        if ai == 0:
            continue
        for j in range(len(b)):
            bj = b[j]
            if bj == 0:
                continue
            deg = (i + j) % r
            res[deg] = (res[deg] + ai * bj) % nmod
            
    return res


def poly_pow(base: List[int], exponent: int, nmod: int, r: int) -> List[int]:
    """Tính lũy thừa đa thức `base`^`exponent` modulo (x^r -1, nmod).
    Không dùng njit để hỗ trợ số mũ (exponent) lớn."""
    
    # Khởi tạo kết quả = 1
    result = [0] * r
    result[0] = 1
    
    b = base[:] 
    e = exponent
    
    while e > 0:
        if e & 1:
            # Chuyển đổi sang NumbaList trước khi gọi hàm JIT
            result_numba = NumbaList(result)
            b_numba = NumbaList(b)
            result = list(poly_mul(result_numba, b_numba, nmod, r))
            
        b_numba = NumbaList(b)
        b = list(poly_mul(b_numba, b_numba, nmod, r))
        e >>= 1
        
    return result

# --- 3. Hàm AKS Chính Đã Tối ưu hóa ---

def is_prime_aks(n: int, verbose: bool = False) -> bool:
    start = time.time()
    
    n_mpz = gmpy2.mpz(n) 
    
    if n_mpz < 2:
        return False

    # Step 1: check perfect power 
    if verbose:
        print("Bước 1: kiểm tra xem có phải lũy thừa hoàn chỉnh không...")
    if is_perfect_power(n): 
        if verbose:
            print("Kết luận: là lũy thừa hoàn chỉnh → hợp số")
        return False

    # Step 2: find r (smallest r such that ord_r(n) > (log_2 n)^2)
    log_n = math.log2(n_mpz)
    max_k = int(math.ceil(log_n ** 2))
    
    # Giới hạn tìm kiếm r: Đặt R_limit = ceil(log_n^3).
    # R_limit được giới hạn tối đa 1 triệu do giới hạn của sieve_primes JIT.
    R_limit = min(1_000_000, int(math.ceil(log_n ** 3)))
    
    if verbose:
        print(f"Bước 2: tìm r (ngưỡng max_k={max_k}, giới hạn R_limit={R_limit})...")
        
    # Tạo danh sách số nguyên tố r_candidates bằng Sàng
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
            # Nếu g == n (tức n chia hết cho r), ta bỏ qua r này và tiếp tục.
            continue
            
        # 2b: Kiểm tra bậc (multiplicative order)
        ordn = multiplicative_order(n, r, max_k) 
        if ordn > max_k:
            found_r = True
            break
            
    # Xử lý trường hợp không tìm thấy r tốt (rất hiếm cho các n nguyên tố)
    if not found_r:
        if verbose:
             print(f"Không tìm thấy r thỏa mãn trong giới hạn R_limit={R_limit}. Kết thúc tìm kiếm.")
        # Dùng r cuối cùng (tối đa R_limit) để kiểm tra các bước còn lại.

    if verbose:
        print(f"Tìm được r = {r} (ord > {max_k})")

    # Step 3: check gcd(a, n) for a <= r (kiểm tra lại cho các số nhỏ hơn r chưa được kiểm tra ở Bước 2)
    if verbose:
        print("Bước 3: kiểm tra các gcd tới r...")
    
    # Chúng ta đã kiểm tra GCD trong quá trình tìm r (chỉ cần đảm bảo kiểm tra hết các số <= r)
    # Vì ta chỉ lặp qua các số nguyên tố, nên ta kiểm tra lại một lần nữa
    for a in range(2, r + 1):
        g = gmpy2.gcd(a, n_mpz) 
        if 1 < g < n_mpz:
            if verbose:
                print(f"Tìm được ước chung không tầm thường {g}: hợp số")
            return False

    # Step 4: if n <= r then n is prime
    if n_mpz <= r:
        if verbose:
            print("n <= r: kết luận là số nguyên tố")
        return True

    # Step 5: check polynomial congruence
    log_n_float = float(log_n)
    limit = int(math.floor(math.sqrt(r - 1) * log_n_float))
    if limit < 1:
        limit = 1
    if verbose:
        print(f"Bước 5: kiểm tra đồng dư đa thức, giới hạn={limit} (r={r})")

    for a in range(1, limit + 1):
        if verbose and a % 10 == 0:
            print(f"  checking a={a}...")
            
        # Đa thức cơ sở (x+a)
        base = [0] * r
        base[0] = a % n  # Hệ số cho x^0 (hằng số a)
        base[1] = 1      # Hệ số cho x^1 (hệ số là 1)
        
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

    parser = argparse.ArgumentParser(description="AKS primality test (Ultimate Optimized)")
    # Dùng string để đọc input lớn
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
        poly_mul(test_list, test_list, 10, 2)
        sieve_primes(10)
    except Exception:
        pass
    
    print(f"Kiểm tra n={n_input} ({len(args.n) // 3} chữ số)...")
    t0 = time.time()
    res = is_prime_aks(n_input, verbose=args.verbose)
    dt = time.time() - t0
    
    print("-" * 30)
    print(f"Kết quả AKS Tối ưu: n là {'số nguyên tố' if res else 'hợp số'} (thời gian {dt:.3f}s)")
    print("-" * 30)