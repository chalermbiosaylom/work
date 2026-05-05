# PWN Shell Control Playbook (Speed + Continuity)

Purpose: maximize exploit loop reliability for local+remote pwn challenges.

## 1) Hybrid Execution Policy

1. Start with `ctf-solve` for fast triage (`file`, `checksec`, `strings`, quick script probes)
2. Switch to `pentest-mcp` once exploit becomes continuous/interactive (menu loops, remote retries)
3. Keep `pentest-mcp` as primary for exploit iteration until stable shell/flag extraction
4. Return to `ctf-solve` for one-shot post-processing only

## 2) Session Continuity Standard

Use persistent tmux session for exploit loops:

- Create session once
- Execute exploit commands in small batches
- Read output in chunks
- Send input only after prompt is confirmed
- If same error repeats 3 times, pivot method immediately

## 3) Pwntools Reliability Pattern

- Prefer deterministic `recvuntil()` anchors before every `sendline()`
- Use explicit timeout handling for blind/slow remotes
- Guard parsing with fallback checks to avoid desync
- Keep stage-1 leak and stage-2 shell logic separated

## 4) ROP / one_gadget Stability

- Always include stack alignment `ret` when needed
- Validate one_gadget constraints before assuming success
- Keep backup chain (`system('/bin/sh')` or ORW) ready

## 5) Debug Loop Optimization

- Local: `gdb` + `pwndbg` (`vmmap`, `telescope`, `canary`, `xinfo`)
- Remote: keep logging minimal but sufficient for regression
- Save first failing payload/sample for replay

## 6) External References Used

- Pwntools tubes docs (tube lifecycle, recv/send reliability)
- one_gadget usage and constraints workflow
- pwndbg command index (`vmmap`, `telescope`, stack/canary helpers)
