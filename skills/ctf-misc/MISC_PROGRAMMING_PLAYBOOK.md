# MISC Programming Playbook (Speed + Continuity)

Purpose: maximize solve speed for programming-style misc challenges while keeping shell/session control stable.

## 1) MCP Routing Strategy (Do we need all MCPs?)

No. Use trigger-based routing, not all tools at once:

- Primary `ctf-solve`: one-shot parsing, script execution, quick transforms
- Primary `pentest-mcp`: interactive jails, persistent loops, long-running judge sessions
- Supplemental `ctf-forensics`: QR/audio/video/rf artifacts
- Supplemental `ctf-reverse`: bytecode/custom VM disassembly when misc crosses into RE

## Hybrid Default (Required)

For hybrid challenges, enforce this sequence:

1. Start with `ctf-solve` for triage (identify format, constraints, quick probes)
2. Switch to `pentest-mcp` when entering continuous exploit/interactive phase
3. Stay in `pentest-mcp` until stateful loop ends
4. Return to `ctf-solve` only for one-shot post-processing/output shaping

## 2) Session Continuity for Interactive Programming/Jails

Use persistent tmux session lifecycle:

1. create session
2. execute command block
3. read output in chunks
4. send next input only after prompt observed
5. if same error repeats 3 times -> pivot method immediately

## 3) Programming Solve Pipeline (Deterministic)

1. Parse constraints and objective
2. Pick complexity budget (`O(n)`, `O(n log n)`, etc.)
3. Start from fast I/O template
4. Implement baseline solution
5. Stress-test with random generator + brute reference
6. Optimize only bottleneck section

## 4) Fast I/O Notes (Python)

- Prefer `sys.stdin.readline` over `input`
- Prefer buffered output patterns for large loops
- Avoid quadratic string concatenation in loops

## 5) Stress-Testing Standard

Inspired by KACTL workflow:

- Keep a brute/reference solver for small constraints
- Generate random test cases
- Compare optimized solver vs brute for many rounds
- Save first mismatch case as repro fixture

## 6) External References Used

- CP-Algorithms index and navigation (algorithm coverage map)
- KACTL testing philosophy (stress tests + CI confidence)
- USACO Guide fast I/O (input/readline performance gap)
