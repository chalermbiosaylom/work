#!/usr/bin/env python3
from __future__ import annotations

import bisect
import heapq
import random
import sys
from collections import Counter, deque
from functools import reduce
from typing import Callable, Iterable, List, Optional, Sequence, Tuple


def read_ints() -> List[int]:
    return list(map(int, sys.stdin.readline().split()))


def prefix_sum(arr: Sequence[int]) -> List[int]:
    out = [0]
    for x in arr:
        out.append(out[-1] + x)
    return out


def binary_search_first_true(lo: int, hi: int, pred: Callable[[int], bool]) -> int:
    while lo < hi:
        mid = (lo + hi) // 2
        if pred(mid):
            hi = mid
        else:
            lo = mid + 1
    return lo


def lower_bound(arr: Sequence[int], x: int) -> int:
    return bisect.bisect_left(arr, x)


def upper_bound(arr: Sequence[int], x: int) -> int:
    return bisect.bisect_right(arr, x)


def bfs_unweighted(n: int, graph: Sequence[Sequence[int]], src: int) -> List[int]:
    dist = [-1] * n
    q = deque([src])
    dist[src] = 0
    while q:
        u = q.popleft()
        for v in graph[u]:
            if dist[v] == -1:
                dist[v] = dist[u] + 1
                q.append(v)
    return dist


def dijkstra(n: int, graph: Sequence[Sequence[Tuple[int, int]]], src: int) -> List[int]:
    inf = 10**30
    dist = [inf] * n
    dist[src] = 0
    pq: List[Tuple[int, int]] = [(0, src)]
    while pq:
        d, u = heapq.heappop(pq)
        if d != dist[u]:
            continue
        for v, w in graph[u]:
            nd = d + w
            if nd < dist[v]:
                dist[v] = nd
                heapq.heappush(pq, (nd, v))
    return dist


class DSU:
    def __init__(self, n: int):
        self.parent = list(range(n))
        self.size = [1] * n

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> bool:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        if self.size[ra] < self.size[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        self.size[ra] += self.size[rb]
        return True


def stress_test(
    gen_case: Callable[[], object],
    brute: Callable[[object], object],
    fast: Callable[[object], object],
    rounds: int = 200,
) -> Tuple[bool, object]:
    for _ in range(rounds):
        case = gen_case()
        b = brute(case)
        f = fast(case)
        if b != f:
            return False, {"case": case, "brute": b, "fast": f}
    return True, {"rounds": rounds}


def sample_case() -> Tuple[List[int], int]:
    n = random.randint(1, 30)
    arr = [random.randint(-20, 20) for _ in range(n)]
    k = random.randint(0, n)
    return arr, k


def brute_k_largest_sum(case: Tuple[List[int], int]) -> int:
    arr, k = case
    return sum(sorted(arr, reverse=True)[:k])


def fast_k_largest_sum(case: Tuple[List[int], int]) -> int:
    arr, k = case
    arr2 = sorted(arr)
    return sum(arr2[len(arr2) - k :])


# ─────────────────────────────────────────────────────────────────────────────
# NUMBER THEORY  (source: PyRival algebra/ — cheran-senthil/PyRival)
# ─────────────────────────────────────────────────────────────────────────────

def gcd(x: int, y: int) -> int:
    """greatest common divisor of x and y"""
    while y:
        x, y = y, x % y
    return x


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """returns gcd, s, r s.t. a*s + b*r == gcd(a, b)"""
    s, old_s = 0, 1
    r, old_r = b, a
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_r, old_s, (old_r - old_s * a) // b if b else 0


lcm = lambda a, b: a * b // gcd(a, b)
gcdm = lambda *args: reduce(gcd, args, 0)
lcmm = lambda *args: reduce(lcm, args, 1)


def modinv(a: int, m: int) -> Optional[int]:
    """modular inverse of a mod m; returns None if gcd(a,m) != 1"""
    g, x, _ = extended_gcd(a % m, m)
    return x % m if g == 1 else None


def is_prime(n: int) -> bool:
    """deterministic Miller-Rabin for n < 3,317,044,064,679,887,385,961,981"""
    if n < 5 or n & 1 == 0 or n % 3 == 0:
        return 2 <= n <= 3
    s = ((n - 1) & (1 - n)).bit_length() - 1
    d = n >> s
    for a in [2, 325, 9375, 28178, 450775, 9780504, 1795265022]:
        p = pow(a, d, n)
        if p == 1 or p == n - 1 or a % n == 0:
            continue
        for _ in range(s):
            p = (p * p) % n
            if p == n - 1:
                break
        else:
            return False
    return True


def prime_list(n: int) -> List[int]:
    """returns a list of primes <= n (wheel-factorised sieve)"""
    res = []
    if n > 1: res.append(2)
    if n > 2: res.append(3)
    if n > 4:
        flag = n % 6 == 2
        sieve = bytearray((n // 3 + flag >> 3) + 1)
        for i in range(1, int(n**0.5) // 3 + 1):
            if not (sieve[i >> 3] >> (i & 7)) & 1:
                k = (3 * i + 1) | 1
                for j in range(k * k // 3, n // 3 + flag, 2 * k):
                    sieve[j >> 3] |= 1 << (j & 7)
                for j in range(k * (k - 2 * (i & 1) + 4) // 3, n // 3 + flag, 2 * k):
                    sieve[j >> 3] |= 1 << (j & 7)
        res.extend([3 * i + 1 | 1 for i in range(1, (n + 1) // 3 + (n % 6 == 1))
                    if not (sieve[i >> 3] >> (i & 7)) & 1])
    return res


def euler_phi_sieve(n: int) -> List[int]:
    """returns list where result[i] = phi(i) for 0 <= i <= n"""
    sieve = [i if i & 1 else i // 2 for i in range(n + 1)]
    for i in range(3, n + 1, 2):
        if sieve[i] == i:
            for j in range(i, n + 1, i):
                sieve[j] = (sieve[j] // i) * (i - 1)
    return sieve


def chinese_remainder(a: List[int], p: List[int]) -> int:
    """CRT for prime moduli: x = a[i] (mod p[i])"""
    prod = reduce(lambda x, y: x * y, p, 1)
    x = [prod // pi for pi in p]
    return sum(a[i] * pow(x[i], p[i] - 2, p[i]) * x[i] for i in range(len(a))) % prod


def composite_crt(b: List[int], m: List[int]) -> Optional[int]:
    """CRT for arbitrary (not necessarily coprime) moduli"""
    x, m_prod = 0, 1
    for bi, mi in zip(b, m):
        g, s, _ = extended_gcd(m_prod, mi)
        if ((bi - x) % mi) % g:
            return None
        x += m_prod * (s * ((bi - x) % mi) // g)
        m_prod = (m_prod * mi) // gcd(m_prod, mi)
    return x % m_prod


def _memodict(f):
    class _md(dict):
        def __missing__(self, key):
            ret = self[key] = f(key)
            return ret
    return _md().__getitem__


def _pollard_rho(n: int) -> int:
    """returns a random factor of n"""
    if n & 1 == 0: return 2
    if n % 3 == 0: return 3
    s = ((n - 1) & (1 - n)).bit_length() - 1
    d = n >> s
    for a in [2, 325, 9375, 28178, 450775, 9780504, 1795265022]:
        p = pow(a, d, n)
        if p == 1 or p == n - 1 or a % n == 0: continue
        for _ in range(s):
            prev = p
            p = (p * p) % n
            if p == 1: return gcd(prev - 1, n)
            if p == n - 1: break
        else:
            for i in range(2, n):
                x, y = i, (i * i + i) % n
                f = gcd(abs(x - y), n)
                while f == 1:
                    x, y = (x * x + i) % n, (y * y + i) % n
                    y = (y * y + i) % n
                    f = gcd(abs(x - y), n)
                if f != n: return f
    return n


@_memodict
def prime_factors(n: int) -> Counter:
    """returns Counter of prime factorization of n (Pollard-Rho, O(n^1/4))"""
    if n <= 1: return Counter()
    f = _pollard_rho(n)
    return Counter([n]) if f == n else prime_factors(f) + prime_factors(n // f)


def discrete_log(a: int, b: int, mod: int) -> Optional[int]:
    """Baby-step Giant-step: smallest x > 0 s.t. pow(a, x, mod) == b"""
    n = int(mod**0.5) + 1
    tiny_step, e = {}, 1
    for j in range(1, n + 1):
        e = e * a % mod
        if e == b: return j
        tiny_step[b * e % mod] = j
    factor = e
    for i in range(2, n + 2):
        e = e * factor % mod
        if e in tiny_step:
            j = tiny_step[e]
            return n * i - j if pow(a, n * i - j, mod) == b else None


def mod_sqrt(a: int, p: int) -> int:
    """Tonelli-Shanks: returns x s.t. x^2 == a (mod p)"""
    a %= p
    if a < 2: return a
    assert pow(a, (p - 1) // 2, p) == 1
    if p & 3 == 3: return pow(a, (p + 1) // 4, p)
    r = ((p - 1) & (1 - p)).bit_length() - 1
    s, n_val = p >> r, 2
    while pow(n_val, (p - 1) // 2, p) != p - 1:
        n_val += 1
    x, b, g = pow(a, (s + 1) // 2, p), pow(a, s, p), pow(n_val, s, p)
    while True:
        t = b
        for m in range(r):
            if t == 1: break
            t = (t * t) % p
        if m == 0: return x
        gs = pow(g, 1 << (r - m - 1), p)
        g, x = (gs * gs) % p, (x * gs) % p
        b, r = (b * g) % p, m


def primitive_root(p: int) -> Optional[int]:
    """returns smallest primitive root of prime p"""
    factors = prime_factors(p - 1)
    for i in range(1, p + 1):
        if all(pow(i, (p - 1) // j, p) != 1 for j in factors):
            return i
    return None


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES  (source: PyRival data_structures/)
# ─────────────────────────────────────────────────────────────────────────────

class FenwickTree:
    """Binary Indexed Tree (Fenwick Tree) for prefix sum queries"""
    def __init__(self, x: List[int]):
        self.bit = list(x)
        for i in range(len(self.bit)):
            j = i | (i + 1)
            if j < len(self.bit):
                self.bit[j] += self.bit[i]

    def update(self, idx: int, x: int) -> None:
        """bit[idx] += x"""
        while idx < len(self.bit):
            self.bit[idx] += x
            idx |= idx + 1

    def query(self, end: int) -> int:
        """returns sum(bit[:end])"""
        x = 0
        while end:
            x += self.bit[end - 1]
            end &= end - 1
        return x

    def range_query(self, lo: int, hi: int) -> int:
        """returns sum(bit[lo:hi])"""
        return self.query(hi) - self.query(lo)

    def findkth(self, k: int) -> int:
        """largest idx s.t. sum(bit[:idx]) <= k"""
        idx = -1
        for d in reversed(range(len(self.bit).bit_length())):
            right_idx = idx + (1 << d)
            if right_idx < len(self.bit) and k >= self.bit[right_idx]:
                idx = right_idx
                k -= self.bit[idx]
        return idx + 1


if __name__ == "__main__":
    ok, info = stress_test(sample_case, brute_k_largest_sum, fast_k_largest_sum, rounds=300)
    print({"ok": ok, "info": info})
