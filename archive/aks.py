"""AKS primality test implementation (pure Python).

This module provides `is_prime_aks(n, verbose=False)` which implements the
AKS primality test and prints progress when `verbose=True`.

Notes:
- This is a straightforward implementation intended for education and
  correctness; it may be slow on very large inputs but works for moderate
  integers (a few hundred bits) for demonstration.
- The algorithm follows the standard steps:
  1) check perfect power
  2) find smallest r with ord_r(n) > (log2 n)^2
  3) check 1 < gcd(a, n) < n for a <= r
  4) if n <= r, declare prime
  5) check polynomial congruences for a up to limit

"""

from __future__ import annotations

import math
import time
from typing import List


def is_perfect_power(n: int) -> bool:
    """Return True if n is a perfect power: n = a^b for integers a>1, b>1."""
    if n < 2:
        return False
    # Try all exponents b from 2 up to log2(n)
    max_b = int(math.log2(n)) + 1
    for b in range(2, max_b + 1):
        # compute integer b-th root via binary search
        low = 2
        high = int(n ** (1.0 / b)) + 2
        while low <= high:
            mid = (low + high) // 2
            p = pow(mid, b)
            if p == n:
                return True
            if p < n:
                low = mid + 1
            else:
                high = mid - 1
    return False


def multiplicative_order(n: int, r: int, limit: int) -> int:
    """Return multiplicative order of n modulo r if <= limit, else return >limit.
    If gcd(n, r) != 1 return 0.
    """
    if math.gcd(n, r) != 1:
        return 0
    x = 1
    value = n % r
    while x <= limit:
        if value == 1:
            return x
        value = (value * n) % r
        x += 1
    return x  # > limit


def poly_mul(a: List[int], b: List[int], nmod: int, r: int) -> List[int]:
    """Multiply polynomials a and b modulo (x^r - 1, nmod).
    Polynomials represented as coefficient lists (lowest power first).
    """
    res = [0] * r
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            if bj == 0:
                continue
            deg = (i + j) % r
            res[deg] = (res[deg] + ai * bj) % nmod
    return res


def poly_pow(base: List[int], exponent: int, nmod: int, r: int) -> List[int]:
    """Exponentiate polynomial `base` to `exponent` under modulus (x^r -1, nmod)."""
    # initialize result = 1
    result = [0] * r
    result[0] = 1
    b = base[:]  # copy
    e = exponent
    while e > 0:
        if e & 1:
            result = poly_mul(result, b, nmod, r)
        b = poly_mul(b, b, nmod, r)
        e >>= 1
    return result


def is_prime_aks(n: int, verbose: bool = False) -> bool:
    start = time.time()
    if n < 2:
        if verbose:
            print("n < 2: không phải số nguyên tố (hợp số)")
        return False

    # Step 1: check perfect power
    if verbose:
        print("Bước 1: kiểm tra xem có phải lũy thừa hoàn chỉnh không...")
    if is_perfect_power(n):
        if verbose:
            print("Kết luận: là lũy thừa hoàn chỉnh → hợp số")
        return False

    # Step 2: find smallest r such that ord_r(n) > (log_2 n)^2
    log_n = math.log2(n)
    max_k = int(math.ceil(log_n ** 2))
    if verbose:
        print(f"Bước 2: tìm r (ngưỡng max_k={max_k})...")
    r = 2
    while True:
        if math.gcd(n, r) == 1:
            ordn = multiplicative_order(n, r, max_k)
            if ordn > max_k:
                break
        r += 1
        # safety: avoid infinite loop; for very small n this will end early
        if r > max(3, int(100 * log_n)) and verbose:
            print(f"Still searching r, current r={r}...")

    if verbose:
        print(f"Tìm được r = {r} (ord > {max_k})")

    # Step 3: check gcd(a, n) for a <= r
    if verbose:
        print("Bước 3: kiểm tra các gcd tới r...")
    for a in range(2, r + 1):
        g = math.gcd(a, n)
        if 1 < g < n:
            if verbose:
                print(f"Tìm được ước chung không tầm thường {g}: hợp số")
            return False

    # Step 4: if n <= r then n is prime
    if n <= r:
        if verbose:
            print("n <= r: kết luận là số nguyên tố")
        return True

    # Step 5: for a = 1 to floor(sqrt(totient(r)) * log n) check polynomial congruence
    # We use the common bound: limit = floor(sqrt(phi(r)) * log n)
    # We approximate phi(r) conservatively by r-1 (phi(r) <= r-1)
    limit = int(math.floor(math.sqrt(r - 1) * log_n))
    if limit < 1:
        limit = 1
    if verbose:
        print(f"Bước 5: kiểm tra đồng dư đa thức, giới hạn={limit} (r={r})")

    # Precompute x polynomial: x corresponds to [0,1,0,0,...]
    for a in range(1, limit + 1):
        if verbose and a % 10 == 0:
            print(f"  checking a={a}...")
        # compute (x + a)^n mod (x^r - 1, n)
        # Đa thức cơ sở (x + a): hệ số x^0 = a, hệ số x^1 = 1, các hệ số khác là 0.
        base = [0] * r
        base[0] = a % n  # Hệ số cho x^0 (hằng số)
        base[1] = 1      # Hệ số cho x^1
        lhs = poly_pow(base, n, n, r)
        # rhs = x^{n mod r} + a
        rhs = [0] * r
        rhs[0] = a % n
        rhs[n % r] = (rhs[n % r] + 1) % n
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

    parser = argparse.ArgumentParser(description="AKS primality test (educational implementation)")
    parser.add_argument("n", type=int, help="Integer to test for primality")
    parser.add_argument("--verbose", action="store_true", help="Show steps")
    args = parser.parse_args()
    res = is_prime_aks(args.n, verbose=args.verbose)
    print(f"Result: n={'prime' if res else 'composite'}")
