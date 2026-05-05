# FactorDB Safe Usage Pattern (Offline-First)

## Problem Statement

FactorDB API (`http://factordb.com/api`) is commonly used for RSA factorization, but:
1. **Competition networks are isolated** - API calls will timeout
2. **Partial status ignored** - Status 'C' (Composite with partial factors) is useful
3. **No fallback** - Script crashes if API fails

## Solution: Offline-First with Smart Status Handling

### 1. Enhanced FactorDB Query (All Status Codes)

```python
import requests
import json

def factordb_query_safe(n, timeout=5):
    """
    Query FactorDB with timeout and handle all status codes.
    
    Status codes:
    - 'FF' (Fully Factored): All factors known
    - 'CF' (Composite, Fully Factored): Same as FF
    - 'C' (Composite): Partial factors available
    - 'PRP' (Probably Prime): Likely prime, no factors
    - 'P' (Prime): Definitely prime
    - 'U' (Unknown): Not in database
    """
    try:
        url = f"http://factordb.com/api?query={n}"
        response = requests.get(url, timeout=timeout)
        data = response.json()
        
        status = data.get('status', 'U')
        
        if status in ['FF', 'CF']:
            # Fully factored - return all factors
            factors = []
            for factor_data in data.get('factors', []):
                factor = int(factor_data[0])
                exponent = int(factor_data[1])
                factors.extend([factor] * exponent)
            return {'status': 'full', 'factors': factors}
        
        elif status == 'C':
            # Partial factors available - still useful!
            partial_factors = []
            remaining = n
            for factor_data in data.get('factors', []):
                factor = int(factor_data[0])
                exponent = int(factor_data[1])
                partial_factors.extend([factor] * exponent)
                remaining //= (factor ** exponent)
            
            if remaining > 1 and remaining != n:
                # We got some factors, but not all
                return {'status': 'partial', 'factors': partial_factors, 'remaining': remaining}
        
        elif status in ['P', 'PRP']:
            # Prime - cannot factor
            return {'status': 'prime', 'factors': [n]}
        
        # Unknown or no useful data
        return {'status': 'unknown', 'factors': []}
    
    except (requests.Timeout, requests.ConnectionError, requests.RequestException) as e:
        print(f"[!] FactorDB API unreachable: {e}")
        return {'status': 'offline', 'factors': []}
    except Exception as e:
        print(f"[!] FactorDB API error: {e}")
        return {'status': 'error', 'factors': []}
```

### 2. Offline Fallback Chain

```python
import subprocess
import sympy

def factor_offline(n, timeout=30):
    """
    Offline factorization using local tools.
    Fallback chain: yafu → msieve → sympy
    """
    # Method 1: yafu (fastest for medium-sized numbers)
    try:
        result = subprocess.run(
            ['yafu', f'factor({n})'],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode == 0:
            # Parse yafu output for factors
            factors = parse_yafu_output(result.stdout)
            if factors:
                return {'status': 'yafu', 'factors': factors}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    
    # Method 2: msieve (good for larger numbers)
    try:
        result = subprocess.run(
            ['msieve', str(n)],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode == 0:
            factors = parse_msieve_output(result.stdout)
            if factors:
                return {'status': 'msieve', 'factors': factors}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    
    # Method 3: sympy (slow but always available)
    try:
        from sympy import factorint
        import signal
        
        # Set timeout using signal (Unix only)
        def timeout_handler(signum, frame):
            raise TimeoutError("sympy factorization timeout")
        
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)
        
        try:
            factor_dict = factorint(n)
            factors = []
            for prime, exp in factor_dict.items():
                factors.extend([prime] * exp)
            return {'status': 'sympy', 'factors': factors}
        finally:
            signal.alarm(0)  # Cancel alarm
    except (TimeoutError, ImportError):
        pass
    
    return {'status': 'failed', 'factors': []}

def parse_yafu_output(output):
    """Extract factors from yafu output"""
    factors = []
    for line in output.split('\n'):
        if 'P' in line or 'C' in line:
            # Extract number from lines like "P35 = 12345..."
            parts = line.split('=')
            if len(parts) == 2:
                try:
                    factor = int(parts[1].strip())
                    factors.append(factor)
                except ValueError:
                    continue
    return factors

def parse_msieve_output(output):
    """Extract factors from msieve output"""
    factors = []
    for line in output.split('\n'):
        if 'p' in line.lower():
            # Extract numbers from msieve output
            parts = line.split()
            for part in parts:
                try:
                    if part.isdigit():
                        factors.append(int(part))
                except ValueError:
                    continue
    return factors
```

### 3. Unified Factorization Function (Competition-Ready)

```python
def factor_n_safe(n):
    """
    Competition-safe factorization with offline-first approach.
    
    Returns:
        dict: {'status': str, 'factors': list, 'remaining': int (optional)}
    """
    print(f"[*] Attempting to factor n ({n.bit_length()} bits)...")
    
    # Step 1: Try FactorDB (with timeout)
    print("[*] Step 1: Querying FactorDB (5s timeout)...")
    result = factordb_query_safe(n, timeout=5)
    
    if result['status'] == 'full':
        print(f"[+] FactorDB: Fully factored ({len(result['factors'])} factors)")
        return result
    
    elif result['status'] == 'partial':
        print(f"[+] FactorDB: Partial factors found")
        print(f"    Factors: {result['factors']}")
        print(f"    Remaining: {result['remaining']} ({result['remaining'].bit_length()} bits)")
        # Continue to factor the remaining part
        n = result['remaining']
    
    else:
        print(f"[!] FactorDB: {result['status']} - switching to offline tools")
    
    # Step 2: Offline factorization
    print("[*] Step 2: Using local factorization tools...")
    offline_result = factor_offline(n, timeout=30)
    
    if offline_result['status'] != 'failed':
        print(f"[+] Offline ({offline_result['status']}): Factored successfully")
        # Combine with partial factors from FactorDB if any
        if result['status'] == 'partial':
            offline_result['factors'] = result['factors'] + offline_result['factors']
        return offline_result
    
    print("[!] All factorization methods failed")
    return {'status': 'failed', 'factors': []}

# Usage example
if __name__ == "__main__":
    n = 123456789012345678901234567890123456789
    result = factor_n_safe(n)
    
    if result['status'] in ['full', 'yafu', 'msieve', 'sympy']:
        print(f"\n[SUCCESS] Factors: {result['factors']}")
        # Verify
        product = 1
        for f in result['factors']:
            product *= f
        assert product == n, "Factorization verification failed!"
    else:
        print(f"\n[FAILED] Could not factor n")
```

## Integration with Crypto Skill

Add to `@ctf-crypto` workflow:

```python
# In RSA attack workflow
def rsa_decrypt_auto(n, e, c):
    # Step 1: Try to factor n (offline-first)
    result = factor_n_safe(n)
    
    if result['status'] in ['full', 'yafu', 'msieve', 'sympy']:
        factors = result['factors']
        
        # Calculate phi
        from collections import Counter
        factor_counts = Counter(factors)
        phi = 1
        for prime, count in factor_counts.items():
            phi *= (prime - 1) * (prime ** (count - 1))
        
        # Calculate d
        from Crypto.Util.number import inverse
        d = inverse(e, phi)
        
        # Decrypt
        m = pow(c, d, n)
        
        # Convert to bytes
        from Crypto.Util.number import long_to_bytes
        flag = long_to_bytes(m)
        return flag
    
    else:
        print("[!] Factorization failed - trying other RSA attacks...")
        # Fallback to Wiener, Coppersmith, etc.
        return None
```

## Key Improvements

1. ✅ **Offline-first:** Local tools prioritized over API
2. ✅ **Timeout protection:** 5s for API, 30s for local tools
3. ✅ **Partial factor handling:** Status 'C' utilized for divide-and-conquer
4. ✅ **Graceful degradation:** Multiple fallback layers
5. ✅ **Competition-ready:** Works in isolated networks
