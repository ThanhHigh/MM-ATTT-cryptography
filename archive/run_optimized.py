# run_optimized.py

from aks_optimized import is_prime_aks
import argparse
import time
import gmpy2
from numba.typed import List as NumbaList # Import để đảm bảo Numba hoạt động

# Làm nóng Numba một lần
try:
    test_list = NumbaList([1, 1])
    is_prime_aks(1, verbose=False) # Gọi thử với input nhỏ
except Exception:
    pass # Bỏ qua lỗi với input nhỏ, mục đích chỉ để làm nóng

def main():
    parser = argparse.ArgumentParser(description="Run optimized AKS primality test on an integer")
    parser.add_argument("n", type=int, help="Integer to test")
    parser.add_argument("--verbose", action="store_true", help="Show step-by-step info")
    args = parser.parse_args()

    t0 = time.time()
    res = is_prime_aks(args.n, verbose=args.verbose)
    dt = time.time() - t0
    
    print("-" * 30)
    print(f"Kiểm tra số: {args.n}")
    print(f"Kết quả AKS Tối ưu: n là {'số nguyên tố' if res else 'hợp số'} (thời gian {dt:.3f}s)")
    print("-" * 30)

if __name__ == "__main__":
    main()