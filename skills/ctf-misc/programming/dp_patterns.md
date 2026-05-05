# DP Patterns for CTF Programming

Source: TheAlgorithms/Python + competitive programming canon.
Use these as **state transition reference** — CTF problems modify the rules, not the structure.

---

## How to Identify DP

Ask: "Can I express the answer as f(subproblem)?"
- Optimal substructure + overlapping subproblems → DP
- Common signals: "maximum/minimum", "count ways", "can reach", "longest/shortest"

**Complexity budget (choose before coding):**

| Constraint N | Max complexity | Approach |
|---|---|---|
| N ≤ 20 | O(2^N × N) | Bitmask DP |
| N ≤ 500 | O(N^2) or O(N^2 log N) | DP 2D |
| N ≤ 5000 | O(N^2) | DP 2D (tight) |
| N ≤ 10^5 | O(N log N) | DP with BIT/monotonic |
| N ≤ 10^6 | O(N) | Linear DP |

---

## 1. 0/1 Knapsack

**State:** `dp[i][w]` = max value using first `i` items with weight limit `w`

```python
def knapsack_01(weights, values, capacity):
    n = len(weights)
    dp = [[0] * (capacity + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for w in range(capacity + 1):
            dp[i][w] = dp[i-1][w]
            if weights[i-1] <= w:
                dp[i][w] = max(dp[i][w], dp[i-1][w - weights[i-1]] + values[i-1])
    return dp[n][capacity]

# Space-optimised (1D):
def knapsack_01_1d(weights, values, capacity):
    dp = [0] * (capacity + 1)
    for w, v in zip(weights, values):
        for j in range(capacity, w - 1, -1):  # reverse to avoid reuse
            dp[j] = max(dp[j], dp[j - w] + v)
    return dp[capacity]
```

**Unbounded knapsack** (can reuse items) — forward loop:
```python
for j in range(w, capacity + 1):  # forward = allows reuse
    dp[j] = max(dp[j], dp[j - w] + v)
```

---

## 2. Longest Common Subsequence (LCS)

**State:** `dp[i][j]` = LCS length of x[:i] and y[:j]

```python
def lcs(x: str, y: str) -> tuple[int, str]:
    m, n = len(x), len(y)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if x[i-1] == y[j-1]:
                dp[i][j] = dp[i-1][j-1] + 1
            else:
                dp[i][j] = max(dp[i-1][j], dp[i][j-1])
    # backtrack
    seq, i, j = "", m, n
    while i > 0 and j > 0:
        if x[i-1] == y[j-1]:
            seq = x[i-1] + seq; i -= 1; j -= 1
        elif dp[i-1][j] >= dp[i][j-1]:
            i -= 1
        else:
            j -= 1
    return dp[m][n], seq
```

**Longest Common Substring** (contiguous — reset on mismatch):
```python
dp[i][j] = dp[i-1][j-1] + 1 if x[i-1] == y[j-1] else 0
```

---

## 3. Longest Increasing Subsequence (LIS) — O(N log N)

```python
import bisect

def lis(arr):
    tails = []
    for x in arr:
        pos = bisect.bisect_left(tails, x)
        if pos == len(tails):
            tails.append(x)
        else:
            tails[pos] = x
    return len(tails)
```

---

## 4. Edit Distance

**State:** `dp[i][j]` = edits to turn x[:i] into y[:j]

```python
def edit_distance(x: str, y: str) -> int:
    m, n = len(x), len(y)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1): dp[i][0] = i
    for j in range(n + 1): dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if x[i-1] == y[j-1]:
                dp[i][j] = dp[i-1][j-1]
            else:
                dp[i][j] = 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
    return dp[m][n]
```

---

## 5. Bitmask DP (Subset over small N)

**Use when:** assigning N items to states, N ≤ 20

```python
# Example: TSP (minimum cost to visit all nodes)
def tsp(dist, n):
    INF = float('inf')
    dp = [[INF] * n for _ in range(1 << n)]
    dp[1][0] = 0  # start at node 0, visited = {0}
    for mask in range(1 << n):
        for u in range(n):
            if dp[mask][u] == INF: continue
            if not (mask >> u & 1): continue
            for v in range(n):
                if mask >> v & 1: continue
                next_mask = mask | (1 << v)
                dp[next_mask][v] = min(dp[next_mask][v], dp[mask][u] + dist[u][v])
    return min(dp[(1 << n) - 1][i] + dist[i][0] for i in range(n))

# Iterating over all subsets of a mask:
def iter_subsets(mask):
    sub = mask
    while sub:
        yield sub
        sub = (sub - 1) & mask
```

---

## 6. Interval DP

**Use when:** splitting a sequence into parts (matrix chain, burst balloons, palindrome partitioning)

```python
# Template: minimum cost of some operation on interval [i,j]
def interval_dp(arr):
    n = len(arr)
    dp = [[0] * n for _ in range(n)]
    for length in range(2, n + 1):          # iterate by length
        for i in range(n - length + 1):
            j = i + length - 1
            dp[i][j] = float('inf')
            for k in range(i, j):           # split point
                dp[i][j] = min(dp[i][j], dp[i][k] + dp[k+1][j] + cost(i, k, j))
    return dp[0][n-1]
```

---

## 7. Floyd-Warshall (All-Pairs Shortest Path)

```python
def floyd_warshall(dist):
    n = len(dist)
    dp = [row[:] for row in dist]
    for k in range(n):
        for i in range(n):
            for j in range(n):
                dp[i][j] = min(dp[i][j], dp[i][k] + dp[k][j])
    return dp
```

---

## 8. Digit DP

**Use when:** count numbers in [0, N] satisfying digit-based constraint.

```python
from functools import lru_cache

def count_numbers(n: int, is_valid) -> int:
    digits = list(map(int, str(n)))
    
    @lru_cache(maxsize=None)
    def dp(pos, tight, started, state):
        if pos == len(digits):
            return 1 if started else 0
        limit = digits[pos] if tight else 9
        result = 0
        for d in range(0, limit + 1):
            new_tight = tight and (d == limit)
            new_started = started or (d > 0)
            new_state = (state, d) if new_started else state
            if is_valid(new_state, d, new_started):
                result += dp(pos + 1, new_tight, new_started, new_state)
        return result
    
    return dp(0, True, False, None)
```

---

## Quick Pattern Matching

| Problem signal | DP type |
|---|---|
| "max value, weight limit" | 0/1 Knapsack |
| "common subsequence/substring" | LCS/LCS-substring |
| "strictly increasing" | LIS |
| "min edits/operations on string" | Edit distance |
| "assign N tasks to N workers" | Bitmask DP |
| "split sequence optimally" | Interval DP |
| "all-pairs distance" | Floyd-Warshall |
| "count N-digit numbers" | Digit DP |
| "game: both play optimally" | Minimax / Game DP |
| "ways to reach from (0,0) to (m,n)" | Grid DP |
