#!/usr/bin/env python3
import argparse
import base64
import json
import math
import pathlib
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from helpers.context_analyzer import ContextAnalyzer
    from helpers.red_herring_detector import analyze_text as detect_red_herring
    from helpers.stage_detector import detect_stages
except Exception:
    ContextAnalyzer = None
    detect_red_herring = None
    detect_stages = None

DEFAULT_BENCHMARK_CASES = "/home/kali/Desktop/.windsurf/skills/ctf-crypto/CRYPTO_BENCHMARK_CASES.json"

SAGE_ATTACKS = {
    "coppersmith",
    "smart",
    "ecc-subgroup",
    "invalid-curve",
    "isogeny",
    "lwe-cvp",
    "lll",
    "cvp",
    "lattice",
}

FLAG_WRAPPER_PATTERNS = [
    re.compile(r"(?:coc2026|rtaf|ctf|flag|f1a9|fl4g|tiger|key)\{[^}\r\n]{1,200}\}", re.IGNORECASE),
    re.compile(r"\{[a-fA-F0-9]{32}\}"),
]

HASH_TOKEN_PATTERNS = [
    re.compile(r"\b[a-fA-F0-9]{32}\b"),
    re.compile(r"\b[a-fA-F0-9]{40}\b"),
]


def select_supplemental_mcp(text: str) -> str:
    if any(k in text for k in ["jwt", "cookie", "authorization", "http", "web token"]):
        return "ctf-web"
    if any(k in text for k in ["pcap", "memory dump", "disk image", "forensics", "artifact"]):
        return "ctf-forensics"
    return ""


def select_handoff_action(text: str) -> str:
    if any(k in text for k in ["jwt", "cookie", "authorization", "http", "web token"]):
        return "handoff-crypto-web-token-validation"
    if any(k in text for k in ["pcap", "memory dump", "disk image", "forensics", "artifact"]):
        return "handoff-crypto-forensics-artifact-decrypt"
    return ""

ATTACK_HINTS: List[Tuple[str, List[str]]] = [
    ("small-e", ["small e", "low exponent", "e=3", "e = 3"]),
    ("wiener", ["wiener", "small d", "large e"]),
    ("fermat", ["fermat", "close primes", "p and q close", "p≈q", "p~q"]),
    ("coppersmith", ["coppersmith", "partial prime", "small roots", "known high bits", "partial bits of p"]),
    ("common-modulus", ["common modulus", "same n", "shared modulus"]),
    ("padding-oracle", ["padding oracle", "padding error", "cbc oracle", "pkcs7"]),
    ("bleichenbacher", ["bleichenbacher", "pkcs#1 v1.5", "pkcs1 v1.5", "bb'98"]),
    ("mt-state-recovery", ["mt19937", "mersenne", "predict next", "random outputs", "prng state"]),
    ("lwe-cvp", ["lwe", "cvp", "lattice", "a,b,q"]),
    ("smart", ["anomalous curve", "smart attack", "ecc anomalous"]),
    ("decode-chain", ["decode chain", "base64", "hex", "multilayer", "fragments"]),
]

PYTHON_ATTACKS = {
    "small-e",
    "wiener",
    "fermat",
    "common-modulus",
    "padding-oracle",
    "bleichenbacher",
    "mt-state-recovery",
    "decode-chain",
    "prng",
}


def decide_tool(attack: str, force_tool: str = "") -> str:
    if force_tool in {"python", "sage"}:
        return force_tool
    if attack in SAGE_ATTACKS:
        return "sage"
    return "python"


def _flatten_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return " ".join(_flatten_text(v) for v in value)
    if isinstance(value, dict):
        return " ".join(_flatten_text(v) for v in value.values())
    return ""


def load_json_file(path: str) -> Any:
    p = pathlib.Path(path).resolve()
    if not p.exists():
        raise SystemExit(f"json file not found: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def run_anti_trap_preflight(artifact: Dict[str, Any]) -> Dict[str, Any]:
    flattened = _flatten_text(artifact)
    primary_source_candidates = _collect_named_values(
        artifact,
        {
            "source",
            "source_code",
            "code",
            "script",
        },
    )
    secondary_source_candidates = _collect_named_values(
        artifact,
        {
            "description",
            "content",
            "text",
            "payload",
        },
    )
    source_texts = [x for x in primary_source_candidates if isinstance(x, str) and x.strip()]
    if not source_texts:
        source_texts = [x for x in secondary_source_candidates if isinstance(x, str) and x.strip()]
    source_text = max(source_texts, key=len) if source_texts else flattened

    context_result: Dict[str, Any] = {"status": "skipped", "reason": "helper unavailable"}
    stage_result: Dict[str, Any] = {"status": "skipped", "reason": "helper unavailable"}
    red_result: Dict[str, Any] = {"status": "skipped", "reason": "helper unavailable"}

    if ContextAnalyzer is not None and source_text.strip():
        try:
            context_result = ContextAnalyzer(source_text).analyze()
        except Exception as ex:
            context_result = {"status": "error", "error": str(ex)}

    if detect_stages is not None and flattened.strip():
        try:
            stage_result = detect_stages(flattened)
        except Exception as ex:
            stage_result = {"status": "error", "error": str(ex)}

    if detect_red_herring is not None and flattened.strip():
        try:
            red_result = detect_red_herring(flattened)
        except Exception as ex:
            red_result = {"status": "error", "error": str(ex)}

    risk_score = 0
    warnings = context_result.get("warnings", []) if isinstance(context_result, dict) else []
    if isinstance(warnings, list):
        risk_score += min(3, len(warnings))

    findings = red_result.get("findings", []) if isinstance(red_result, dict) else []
    if isinstance(findings, list):
        for f in findings:
            severity = str(f.get("severity", "")).lower() if isinstance(f, dict) else ""
            if severity == "high":
                risk_score += 2
            elif severity == "medium":
                risk_score += 1

    estimated_stages = 0
    if isinstance(stage_result, dict):
        estimated_stages = int(stage_result.get("estimated_stages", 0) or 0)
    if estimated_stages >= 2:
        risk_score += 1

    risk_level = "low"
    if risk_score >= 5:
        risk_level = "high"
    elif risk_score >= 2:
        risk_level = "medium"

    return {
        "enabled": True,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "context": context_result,
        "stages": stage_result,
        "red_herring": red_result,
    }


def apply_context_enrichment(artifact: Dict[str, Any], preflight: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    if not isinstance(artifact, dict):
        return artifact, []
    enriched = dict(artifact)
    updates: List[str] = []

    context = preflight.get("context", {}) if isinstance(preflight, dict) else {}
    best = context.get("best", {}) if isinstance(context, dict) else {}

    for key in ("n", "e", "c"):
        if key in enriched:
            continue
        entry = best.get(key)
        if isinstance(entry, dict) and isinstance(entry.get("value"), int):
            enriched[key] = entry["value"]
            updates.append(key)

    return enriched, updates


def _try_parse_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except Exception:
            return None
    return None


def _collect_named_values(value: Any, names: Set[str]) -> List[Any]:
    out: List[Any] = []
    if isinstance(value, dict):
        for k, v in value.items():
            if str(k).lower() in names:
                out.append(v)
            out.extend(_collect_named_values(v, names))
    elif isinstance(value, list):
        for v in value:
            out.extend(_collect_named_values(v, names))
    return out


def _first_int(artifact: Dict[str, Any], candidate_names: List[str]) -> Optional[int]:
    names = {n.lower() for n in candidate_names}
    for raw in _collect_named_values(artifact, names):
        parsed = _try_parse_int(raw)
        if parsed is not None:
            return parsed
    return None


def _int_to_bytes(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    size = (int(value).bit_length() + 7) // 8
    return int(value).to_bytes(size, "big")


def _extract_flags_from_text(text: str, allow_hash_tokens: bool = True) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()

    for rx in FLAG_WRAPPER_PATTERNS:
        for m in rx.finditer(text):
            token = m.group(0)
            if token not in seen:
                seen.add(token)
                out.append(token)

    if not out and allow_hash_tokens:
        for rx in HASH_TOKEN_PATTERNS:
            for m in rx.finditer(text):
                token = m.group(0)
                if token not in seen:
                    seen.add(token)
                    out.append(token)

    return out


def _extract_flags_from_bytes(data: bytes, allow_hash_tokens: bool = True) -> List[str]:
    return _extract_flags_from_text(data.decode("utf-8", errors="ignore"), allow_hash_tokens=allow_hash_tokens)


def _preview(data: bytes, limit: int = 200) -> str:
    return data.decode("utf-8", errors="ignore").replace("\n", " ").replace("\r", " ")[:limit]


def _iroot_exact(n: int, k: int) -> Tuple[int, bool]:
    if n < 0:
        return 0, False
    if n in (0, 1):
        return n, True
    if k <= 1:
        return n, True

    lo, hi = 0, 1
    while hi**k <= n:
        hi <<= 1
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        p = mid**k
        if p == n:
            return mid, True
        if p < n:
            lo = mid
        else:
            hi = mid
    return lo, lo**k == n


def _egcd(a: int, b: int) -> Tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def _modinv(a: int, m: int) -> Optional[int]:
    g, x, _ = _egcd(a, m)
    if g != 1:
        return None
    return x % m


def _small_e_attack(n: int, e: int, c: int, max_k: int = 1000) -> Optional[Dict[str, Any]]:
    if e <= 1 or e > 100:
        return None
    for k in range(max_k):
        candidate = c + (k * n)
        m, exact = _iroot_exact(candidate, e)
        if exact and pow(m, e, n) == c:
            return {"m": m, "k_offset": k}
    return None


def _fermat_factor(n: int, max_iterations: int = 100000) -> Optional[Tuple[int, int]]:
    if n % 2 == 0:
        return 2, n // 2
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    b2 = a * a - n

    for _ in range(max_iterations):
        b = math.isqrt(b2)
        if b * b == b2:
            p = a + b
            q = a - b
            if p > 1 and q > 1 and p * q == n:
                return p, q
        a += 1
        b2 = a * a - n
    return None


def _fermat_attack(n: int, e: int, c: int, max_iterations: int = 100000) -> Optional[Dict[str, Any]]:
    factors = _fermat_factor(n, max_iterations=max_iterations)
    if not factors:
        return None
    p, q = factors
    phi = (p - 1) * (q - 1)
    d = _modinv(e, phi)
    if d is None:
        return None
    return {"m": pow(c, d, n), "p": p, "q": q, "d": d}


def _continued_fraction(num: int, den: int) -> List[int]:
    out: List[int] = []
    while den:
        a = num // den
        out.append(a)
        num, den = den, num - a * den
    return out


def _convergents(cf: List[int]) -> List[Tuple[int, int]]:
    conv: List[Tuple[int, int]] = []
    p0, p1 = 0, 1
    q0, q1 = 1, 0
    for a in cf:
        p = a * p1 + p0
        q = a * q1 + q0
        conv.append((p, q))
        p0, p1 = p1, p
        q0, q1 = q1, q
    return conv


def _wiener_attack(n: int, e: int, c: int) -> Optional[Dict[str, Any]]:
    for k, d in _convergents(_continued_fraction(e, n)):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue

        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - (4 * n)
        if disc < 0:
            continue
        root = math.isqrt(disc)
        if root * root != disc:
            continue
        if (s + root) % 2 != 0:
            continue
        p = (s + root) // 2
        q = (s - root) // 2
        if p > 1 and q > 1 and p * q == n:
            return {"m": pow(c, d, n), "d": d, "p": p, "q": q}
    return None


def _common_modulus_attack(n: int, e1: int, c1: int, e2: int, c2: int) -> Optional[Dict[str, Any]]:
    g, a, b = _egcd(e1, e2)
    if g != 1:
        return None

    if a < 0:
        inv = _modinv(c1, n)
        if inv is None:
            return None
        c1 = inv
        a = -a

    if b < 0:
        inv = _modinv(c2, n)
        if inv is None:
            return None
        c2 = inv
        b = -b

    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return {"m": m, "s": a, "t": b}


def _candidate_text_values(artifact: Dict[str, Any]) -> List[str]:
    names = {
        "data",
        "payload",
        "blob",
        "text",
        "ciphertext",
        "encoded",
        "message",
        "content",
    }
    out: List[str] = []
    for v in _collect_named_values(artifact, names):
        if isinstance(v, str) and v.strip():
            out.append(v.strip())
    flattened = _flatten_text(artifact).strip()
    if flattened:
        out.append(flattened)
    return out


def _decode_chain_candidate(seed: bytes, max_depth: int = 6) -> Dict[str, Any]:
    best = {
        "decoded": seed,
        "chain": [],
        "flags": _extract_flags_from_bytes(seed),
        "score": len(_extract_flags_from_bytes(seed)) * 100 + (1 if b"{" in seed else 0),
    }

    queue: List[Tuple[bytes, List[str], int]] = [(seed, [], 0)]
    seen: Set[bytes] = {seed}

    while queue:
        current, chain, depth = queue.pop(0)
        text = current.decode("utf-8", errors="ignore")
        flags = _extract_flags_from_text(text)
        score = len(flags) * 100 + (1 if "{" in text else 0) + (1 if "}" in text else 0)
        if score > best["score"]:
            best = {"decoded": current, "chain": chain, "flags": flags, "score": score}
            if flags:
                break

        if depth >= max_depth:
            continue

        candidates: List[Tuple[str, bytes]] = []

        stripped = text.strip()
        if stripped and len(stripped) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", stripped):
            try:
                candidates.append(("hex", bytes.fromhex(stripped)))
            except Exception:
                pass

        if stripped:
            try:
                decoded_b64 = base64.b64decode(stripped, validate=True)
                if decoded_b64:
                    candidates.append(("base64", decoded_b64))
            except Exception:
                pass

        rev = current[::-1]
        if rev != current:
            candidates.append(("reverse", rev))

        for method, nxt in candidates:
            if nxt in seen or not nxt:
                continue
            seen.add(nxt)
            queue.append((nxt, [*chain, method], depth + 1))

    return best


def _decode_chain_attack(artifact: Dict[str, Any]) -> Dict[str, Any]:
    best: Optional[Dict[str, Any]] = None

    for candidate in _candidate_text_values(artifact):
        seed = candidate.encode("utf-8", errors="ignore")
        result = _decode_chain_candidate(seed)
        if best is None or result["score"] > best["score"]:
            best = result
            if result.get("flags"):
                break

    if best is None:
        return {
            "status": "failed",
            "attack": "decode-chain",
            "flags": [],
            "flag": None,
            "plaintext_preview": "",
            "details": {"chain": []},
            "message": "No decodable payload found",
        }

    decoded = best["decoded"]
    flags = best.get("flags") or _extract_flags_from_bytes(decoded)
    return {
        "status": "success" if flags else "failed",
        "attack": "decode-chain",
        "flags": flags,
        "flag": flags[0] if flags else None,
        "plaintext_preview": _preview(decoded),
        "details": {"chain": best.get("chain", [])},
        "message": "ok" if flags else "Decode chain explored but no verified flag wrapper found",
    }


def _build_math_success(attack: str, data: Dict[str, Any]) -> Dict[str, Any]:
    m = int(data.get("m", 0))
    plaintext = _int_to_bytes(m)
    flags = _extract_flags_from_bytes(plaintext)
    return {
        "status": "success" if flags else "partial",
        "attack": attack,
        "flags": flags,
        "flag": flags[0] if flags else None,
        "plaintext_preview": _preview(plaintext),
        "details": data,
        "message": "ok" if flags else "decryption succeeded but no wrapped flag extracted",
    }


def run_builtin_attack(attack: str, artifact: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not artifact:
        return None

    if attack == "decode-chain":
        return _decode_chain_attack(artifact)

    if attack == "common-modulus":
        n = _first_int(artifact, ["n", "modulus"])
        e1 = _first_int(artifact, ["e1", "e"])
        c1 = _first_int(artifact, ["c1", "c", "ciphertext"])
        e2 = _first_int(artifact, ["e2"])
        c2 = _first_int(artifact, ["c2"])
        if None in {n, e1, c1, e2, c2}:
            return {
                "status": "failed",
                "attack": attack,
                "flags": [],
                "flag": None,
                "plaintext_preview": "",
                "details": {},
                "message": "missing required fields for common-modulus (n,e1,c1,e2,c2)",
            }
        got = _common_modulus_attack(int(n), int(e1), int(c1), int(e2), int(c2))
        if not got:
            return {
                "status": "failed",
                "attack": attack,
                "flags": [],
                "flag": None,
                "plaintext_preview": "",
                "details": {},
                "message": "common modulus attack prerequisites not satisfied",
            }
        return _build_math_success(attack, got)

    if attack not in {"small-e", "wiener", "fermat"}:
        return None

    n = _first_int(artifact, ["n", "modulus"])
    e = _first_int(artifact, ["e", "exponent"])
    c = _first_int(artifact, ["c", "ciphertext"])
    if None in {n, e, c}:
        return {
            "status": "failed",
            "attack": attack,
            "flags": [],
            "flag": None,
            "plaintext_preview": "",
            "details": {},
            "message": "missing required fields (n,e,c)",
        }

    result: Optional[Dict[str, Any]]
    if attack == "small-e":
        result = _small_e_attack(int(n), int(e), int(c))
    elif attack == "wiener":
        result = _wiener_attack(int(n), int(e), int(c))
    else:
        result = _fermat_attack(int(n), int(e), int(c))

    if not result:
        return {
            "status": "failed",
            "attack": attack,
            "flags": [],
            "flag": None,
            "plaintext_preview": "",
            "details": {},
            "message": f"{attack} did not succeed",
        }

    return _build_math_success(attack, result)


def infer_attack_from_artifact(artifact: Dict[str, Any]) -> Tuple[str, int, List[str]]:
    explicit = str(artifact.get("attack", "")).strip().lower()
    if explicit:
        return explicit, 9, ["attack field provided in artifact"]

    tokens_src = _flatten_text(artifact).lower()
    tokens_src = re.sub(r"\s+", " ", tokens_src).strip()

    scores: Dict[str, int] = {}
    reasons: Dict[str, List[str]] = {}

    for attack, hints in ATTACK_HINTS:
        for hint in hints:
            if hint in tokens_src:
                scores[attack] = scores.get(attack, 0) + 1
                reasons.setdefault(attack, []).append(hint)

    if not scores:
        return "decode-chain", 4, ["fallback: no strong hints found"]

    best_attack = max(scores, key=lambda k: scores[k])
    score = scores[best_attack]
    confidence = min(9, 4 + score)
    matched = reasons.get(best_attack, [])
    return best_attack, confidence, [f"matched hints: {', '.join(matched)}"]


def make_solver_stub(attack: str, tool: str, out_path: pathlib.Path) -> None:
    if tool == "sage":
        code = f'''#!/usr/bin/env sage
import json

# TODO: Implement {attack} in SageMath
result = {{
    "status": "todo",
    "attack": "{attack}",
    "tool": "sage",
    "flags": [],
    "notes": "Implement Sage attack body here"
}}
print(json.dumps(result, indent=2, ensure_ascii=False))
'''
    else:
        code = f'''#!/usr/bin/env python3
import json

# TODO: Implement {attack} in Python
result = {{
    "status": "todo",
    "attack": "{attack}",
    "tool": "python",
    "flags": [],
    "notes": "Implement Python attack body here"
}}
print(json.dumps(result, indent=2, ensure_ascii=False))
'''
    out_path.write_text(code, encoding="utf-8")
    out_path.chmod(0o755)


def run_solver(tool: str, solver_path: pathlib.Path) -> Dict:
    if tool == "sage":
        cmd = ["sage", str(solver_path)]
    else:
        cmd = [sys.executable, str(solver_path)]

    proc = subprocess.run(cmd, text=True, capture_output=True)
    output = proc.stdout.strip() or proc.stderr.strip()

    parsed = None
    if output:
        try:
            parsed = json.loads(output)
        except Exception:
            parsed = {"raw_output": output}

    return {
        "return_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "parsed": parsed,
    }


def benchmark_mode(cases_path: str, pass_threshold: float) -> Dict[str, Any]:
    raw = load_json_file(cases_path)
    if not isinstance(raw, list):
        raise SystemExit("benchmark cases json must be a list")

    rows: List[Dict[str, Any]] = []
    total = 0
    earned = 0
    generated_plans: Dict[str, str] = {}

    for c in raw:
        if not isinstance(c, dict):
            continue
        name = str(c.get("name", "unnamed_case"))
        attack, conf, why = infer_attack_from_artifact(c)
        tool = decide_tool(attack)
        txt = re.sub(r"\s+", " ", _flatten_text(c).lower()).strip()
        supplemental_mcp = select_supplemental_mcp(txt)
        handoff_action = select_handoff_action(txt)
        plan_line = (
            f"AttackPlan: attack={attack} | tool={tool} | solver=program | "
            f"supplemental_mcp={supplemental_mcp or 'none'} | "
            f"handoff_action={handoff_action or 'none'} | confidence={conf}"
        )
        generated_plans[name] = plan_line

        score = 0
        issues: List[str] = []
        total += 6

        exp_attack = str(c.get("expected_attack", ""))
        exp_tool = str(c.get("expected_tool", ""))
        exp_solver = str(c.get("expected_solver_type", "program"))

        if attack == exp_attack:
            score += 1
        else:
            issues.append(f"attack: expected={exp_attack}, got={attack}")

        if tool == exp_tool:
            score += 1
        else:
            issues.append(f"tool: expected={exp_tool}, got={tool}")

        if "program" == exp_solver:
            score += 1
        else:
            issues.append(f"solver: expected={exp_solver}, got=program")

        exp_supplemental = str(c.get("expected_supplemental_mcp", ""))
        if supplemental_mcp == exp_supplemental:
            score += 1
        else:
            issues.append(f"supplemental_mcp: expected={exp_supplemental}, got={supplemental_mcp}")

        exp_handoff = str(c.get("expected_handoff_action", ""))
        if handoff_action == exp_handoff:
            score += 1
        else:
            issues.append(f"handoff_action: expected={exp_handoff}, got={handoff_action}")

        if conf >= 4:
            score += 1
        else:
            issues.append("confidence: expected integer >= 4")

        earned += score
        rows.append(
            {
                "name": name,
                "score": score,
                "max_score": 6,
                "status": "pass" if score == 6 else "partial",
                "issues": issues,
                "inference_notes": why,
                "supplemental_mcp": supplemental_mcp,
                "handoff_action": handoff_action,
                "attack_plan": plan_line,
            }
        )

    acc = earned / total if total else 0.0
    return {
        "summary": {
            "cases": len(rows),
            "earned_points": earned,
            "max_points": total,
            "accuracy": round(acc, 4),
            "pass_threshold": pass_threshold,
            "passed": acc >= pass_threshold,
        },
        "results": rows,
        "generated_plans": generated_plans,
    }


def infer_many_artifacts(artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for idx, artifact in enumerate(artifacts, start=1):
        attack, conf, notes = infer_attack_from_artifact(artifact)
        tool = decide_tool(attack)
        txt = re.sub(r"\s+", " ", _flatten_text(artifact).lower()).strip()
        supplemental_mcp = select_supplemental_mcp(txt)
        handoff_action = select_handoff_action(txt)
        plan = (
            f"AttackPlan: attack={attack} | tool={tool} | solver=program | "
            f"supplemental_mcp={supplemental_mcp or 'none'} | "
            f"handoff_action={handoff_action or 'none'} | confidence={conf}"
        )
        rows.append(
            {
                "index": idx,
                "attack": attack,
                "tool": tool,
                "execution_mode": "hybrid",
                "supplemental_mcp": supplemental_mcp,
                "handoff_action": handoff_action,
                "confidence": conf,
                "attack_plan": plan,
                "inference_notes": notes,
            }
        )
    return {
        "summary": {
            "artifacts": len(rows),
            "execution_mode": "hybrid",
        },
        "results": rows,
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Crypto solver scaffold with auto Python/Sage tool switch")
    p.add_argument("--attack", default="", help="attack name, e.g. small-e, lwe-cvp, smart")
    p.add_argument("--input-json", default="", help="challenge_artifacts.json for auto attack inference")
    p.add_argument("--solver", default="", help="existing solver path (optional)")
    p.add_argument("--workdir", default=".", help="directory to create solver stub")
    p.add_argument("--force-tool", choices=["python", "sage"], default="")
    p.add_argument("--benchmark-mode", action="store_true", help="evaluate auto plans against benchmark cases")
    p.add_argument("--benchmark-cases", default=DEFAULT_BENCHMARK_CASES, help="benchmark cases JSON path")
    p.add_argument("--pass-threshold", type=float, default=0.85, help="benchmark pass threshold")
    p.add_argument("--no-preflight", action="store_true", help="disable anti-trap preflight analysis on artifact")
    p.add_argument("--dry-run", action="store_true", help="only show plan, do not execute")
    p.add_argument("--json", action="store_true", help="emit JSON output")
    args = p.parse_args()

    if args.benchmark_mode:
        bench = benchmark_mode(args.benchmark_cases, args.pass_threshold)
        if args.json:
            print(json.dumps(bench, indent=2, ensure_ascii=False))
        else:
            s = bench["summary"]
            print(
                f"benchmark: accuracy={s['accuracy']:.4f} "
                f"({s['earned_points']}/{s['max_points']}) passed={s['passed']}"
            )
            for r in bench["results"]:
                print(f"- {r['name']}: {r['score']}/{r['max_score']} [{r['status']}]")
        return

    artifact_data: Dict[str, Any] = {}
    artifact_list: List[Dict[str, Any]] = []
    inferred_notes: List[str] = []
    inferred_conf = 6

    if args.input_json:
        loaded = load_json_file(args.input_json)
        if isinstance(loaded, dict):
            artifact_data = loaded
        elif isinstance(loaded, list) and loaded and isinstance(loaded[0], dict):
            artifact_list = [x for x in loaded if isinstance(x, dict)]
            artifact_data = artifact_list[0]
        else:
            raise SystemExit("input json must be an object or a non-empty list of objects")

    if not args.attack and len(artifact_list) > 1:
        multi = infer_many_artifacts(artifact_list)
        if args.json:
            print(json.dumps(multi, indent=2, ensure_ascii=False))
        else:
            print(f"artifacts={multi['summary']['artifacts']}")
            for r in multi["results"]:
                print(f"[{r['index']}] {r['attack_plan']}")
        return

    attack = args.attack.strip().lower()
    if not attack:
        if not artifact_data:
            raise SystemExit("provide --attack or --input-json (or use --benchmark-mode)")
        attack, inferred_conf, inferred_notes = infer_attack_from_artifact(artifact_data)

    anti_trap_preflight: Dict[str, Any] = {"enabled": False, "reason": "disabled" if args.no_preflight else "no artifact"}
    artifact_for_execution = artifact_data
    enriched_fields: List[str] = []
    if artifact_data and not args.no_preflight:
        anti_trap_preflight = run_anti_trap_preflight(artifact_data)
        artifact_for_execution, enriched_fields = apply_context_enrichment(artifact_data, anti_trap_preflight)
    elif artifact_data:
        anti_trap_preflight = {"enabled": False, "reason": "disabled"}

    tool = decide_tool(attack, args.force_tool)

    workdir = pathlib.Path(args.workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)

    if args.solver:
        solver_path = pathlib.Path(args.solver).resolve()
    else:
        suffix = ".sage" if tool == "sage" else ".py"
        solver_path = workdir / f"solve_{attack.replace('-', '_')}{suffix}"
        should_create_stub = not args.dry_run and not solver_path.exists() and (
            tool == "sage" or not artifact_data
        )
        if should_create_stub:
            make_solver_stub(attack, tool, solver_path)

    input_text = re.sub(r"\s+", " ", _flatten_text(artifact_for_execution).lower()).strip() if artifact_for_execution else ""
    supplemental_mcp = select_supplemental_mcp(input_text)
    handoff_action = select_handoff_action(input_text)
    plan_line = (
        f"AttackPlan: attack={attack} | tool={tool} | solver=program | "
        f"supplemental_mcp={supplemental_mcp or 'none'} | "
        f"handoff_action={handoff_action or 'none'} | confidence={inferred_conf}"
    )

    result = {
        "attack": attack,
        "execution_mode": "hybrid",
        "tool": tool,
        "supplemental_mcp": supplemental_mcp,
        "handoff_action": handoff_action,
        "solver_path": str(solver_path),
        "attack_plan": plan_line,
        "dry_run": args.dry_run,
        "inferred": bool(not args.attack and artifact_data),
        "inference_notes": inferred_notes,
        "anti_trap_preflight": anti_trap_preflight,
        "artifact_enriched_fields": enriched_fields,
    }

    if not args.dry_run:
        builtin = run_builtin_attack(attack, artifact_for_execution) if tool == "python" else None
        if builtin is not None:
            result["execution"] = {
                "engine": "builtin",
                "return_code": 0 if builtin.get("status") in {"success", "partial"} else 1,
                "stdout": json.dumps(builtin, ensure_ascii=False),
                "stderr": "",
                "parsed": builtin,
            }
        else:
            result["execution"] = run_solver(tool, solver_path)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(plan_line)
        print(f"solver_path={solver_path}")
        if not args.dry_run:
            rc = result.get("execution", {}).get("return_code")
            print(f"return_code={rc}")


if __name__ == "__main__":
    main()
