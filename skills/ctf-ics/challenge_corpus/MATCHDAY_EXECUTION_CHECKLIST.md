# MATCH-DAY EXECUTION CHECKLIST (1-Page)

Use this page as your live runbook during competition.

## 0) Objective Mode (Always ON)
- Attempt **every challenge**, regardless of score.
- Optimize for **speed + correctness + reproducibility**.
- Prefer prepared tools/workflows over ad-hoc/manual paths.

---

## 1) 30-Second Triage
For every new challenge folder, run immediately:

```bash
file *
ls -lah
cat README* 2>/dev/null
```

Then classify fast:
- PCAP / network trace -> forensics/network path
- Modbus/ENIP/ICS service -> ICS protocol path
- Binary / script / unknown -> reverse/pwn path

Decision target: **pick first execution path within 30s**.

---

## 2) Command Presets (Copy-Run)
Replace `<TARGET_IP>` and `<PORT>` only.

### A) Reachability preflight
```bash
nc -zvw 3 <TARGET_IP> <PORT>
```

### B) Modbus quick map + read
```bash
/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 \
/home/kali/Desktop/.windsurf/skills/ctf-ics/tools/modbus/modbus_connect_test.py \
--ip <TARGET_IP> --port 502 --full-scan --json

/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 \
/home/kali/Desktop/.windsurf/skills/ctf-ics/tools/modbus/modbus_read_find_flags.py \
--ip <TARGET_IP> --port 502 --probe-units --reg-start 0 --reg-end 512 --json
```

### C) ENIP identity + sweep
```bash
/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 \
/home/kali/Desktop/.windsurf/skills/ctf-ics/tools/enip/enip_list_identity.py \
--ip <TARGET_IP> --port 44818 --json

/home/kali/Desktop/RTAF-CTF-2026/OT-Security-Lab/.venv/bin/python3 \
/home/kali/Desktop/.windsurf/skills/ctf-ics/tools/enip/enip_cpppo_read_find_flags.py \
--ip <TARGET_IP> --port 44818 --auto-sweep --sweep-range 1-50 --sweep-attrs 1-10 --json
```

### D) Fast replay (strict profile)
```bash
python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus/replay_harness.py \
--protocols modbus,enip \
--include-ids modbus_illuminated_pcap,enip_pcap_flag_forensics_pattern \
--timeout 20 --json
```

### E) Regenerate profile from latest replay
```bash
python3 /home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus/build_matchday_profile.py \
--replay-dir /home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus \
--output /home/kali/Desktop/.windsurf/skills/ctf-ics/challenge_corpus/matchday_only_profile.json \
--max-ttr-sec 2.0 --timeout 20 --top-service-up 12 --min-executed-cases 8 \
--weight-success 60 --weight-ttr 25 --weight-semantic-clean 15 \
--min-score 5 --protocol-balance-mode strict
```

---

## 3) Pivot Rules (Hard)
Pivot immediately if one of these is true:
- Same error repeats **3 times**.
- Network request/tool call exceeds **5 seconds** repeatedly.
- ENIP parser returns constant unknown/empty set with no progress.
- Service appears down (`connection refused`, `no route`, `timeout`) after preflight retry.

Pivot order:
1. Protocol-native read path
2. PCAP/offline artifact extraction
3. Fallback decoding pipeline (utf16/denull/base64/hex)
4. Alternative toolset in same protocol family

---

## 4) Fail-Fast Conditions
Stop current path and switch when:
- No new artifact/indicator after 2 command cycles.
- Output lacks target provenance (cannot tie data to address/tag/packet).
- Candidate text fails strict format checks repeatedly.
- Tool crashes from dependency/arg mismatch.

Never keep brute forcing blind when state-gate evidence is missing.

---

## 5) Evidence & Flag Acceptance
Accept candidate only if all hold:
- Extracted from real output/file/packet (not guessed).
- Traceable source (register/tag/packet offset/path).
- Survives decode chain verification.
- Not known decoy pattern.

---

## 6) Team Loop (per challenge)
- T+0:30 -> Path chosen
- T+2:00 -> First artifact obtained
- T+5:00 -> Flag or pivot to next method
- T+8:00 -> Escalate/rotate, do not stall queue

Keep queue moving; breadth + speed beats overfitting one stuck task.
