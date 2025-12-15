"""Runner for the AKS implementation.

Usage examples (Windows cmd):
  python run_aks.py 101 --verbose
  python run_aks.py 1234567891011

This script reads an integer from the command line and runs the AKS test
printing the steps and final result.
"""

from aks import is_prime_aks
import argparse
import time


def main():
    parser = argparse.ArgumentParser(description="Run AKS primality test on an integer")
    parser.add_argument("n", type=int, help="Integer to test")
    parser.add_argument("--verbose", action="store_true", help="Show step-by-step info")
    args = parser.parse_args()

    t0 = time.time()
    res = is_prime_aks(args.n, verbose=args.verbose)
    dt = time.time() - t0
    print(f"Kết quả AKS: n là {'số nguyên tố' if res else 'hợp số'} (thời gian {dt:.3f}s)")


if __name__ == "__main__":
    main()
