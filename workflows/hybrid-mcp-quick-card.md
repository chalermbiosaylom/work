---
description: Hybrid MCP Quick Card for fast lane selection and stall fallback in CTF match mode
---

# Hybrid MCP Quick Card (1 Page)

Use this card for fast MCP lane decisions in competition.

## 0) Default Rule (Start Here)

- Start with `ctf-solve` for one-shot recon/read/decode.
- Escalate to `pentest-mcp` only when interactive/session-bound/stateful behavior is required.
- Keep one active MCP lane per branch.

## 1) 10-Second Lane Selector

Choose `ctf-solve` when most are true:

- [ ] Task is one-shot or short bounded command.
- [ ] Read-first enumeration / decode chain.
- [ ] No interactive prompt expected.
- [ ] No requirement to hold persistent shell/session.
- [ ] No strict state continuity requirement between actions.

Choose `pentest-mcp` when any are true:

- [ ] Need persistent shell/session (`create_session`, `send_input`, `read_output`).
- [ ] Service is interactive or prompt-driven.
- [ ] Stateful write logic needs same session continuity.
- [ ] Long-running process with trigger-based monitoring is required.
- [ ] Multi-step exploit requires controlled I/O in one session.

## 2) Stall Fallback Rule (Mandatory)

If `pentest-mcp` branch stalls:

1. Wait up to `20-30s` for new output.
2. Retry once with a fresh session.
3. If still stalled, emit pivot and move branch back to `ctf-solve`.

Template:

```text
[PIVOT] reason=pentest_mcp_stall count=2 from=pentest-mcp to=ctf-solve scope_ok=true
```

## 3) ICS Lane Mapping (Quick)

- Port `502/44818/102/4840/47808`: start `ctf-solve` read-first path.
- Move to `pentest-mcp` for stateful write or interactive control loops.
- Use `sharkmcp`/`wiremcp` for PCAP-heavy branches.
- Use `ghidramcp` for firmware/binary reverse branches.

## 4) Safety Hooks Before Write (ICS)

- Lock target tuple first (`host/ip/port/unit/protocol`).
- Confirm reachability (`nc -zvw 10` or `nmap -Pn -p<port>`).
- Capture baseline snapshot before FC05/FC06/FC0F/FC10.
- If contamination/drift appears: rollback from baseline first, then reset only if rollback fails.

## 5) Flag Halt Protocol

On validated flag hit, stop immediately and output exactly:

```text
[FLAG] <raw_flag>
[CLEAN] <sanitized_flag>
[METHOD] <1-line extraction command or decode chain>
```
