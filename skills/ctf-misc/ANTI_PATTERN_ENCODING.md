# AI Anti-Patterns: Encoding & Parsing Challenges

## Quick Reference Card

### 🚨 Top 5 AI Failure Modes

1. **Whitespace Blindness** - Ignoring spaces/width, counting only visible chars
2. **Pattern Over-Engineering** - Hardcoded lookup tables instead of math formulas
3. **Wrong Detection Order** - Generic patterns before specific ones
4. **Boundary Guessing** - Looking ahead instead of using exact dimensions
5. **Dimension Mismatch** - Not validating geometric constraints (n×n, width==height)

### ✅ Correct Approach Checklist

```python
# Before parsing ANY encoding:
□ Check len(line) not just line.count(char)
□ Detect patterns with spaces/mixed content FIRST
□ Use geometric formulas (r=(w-1)/2) not lookup tables
□ Consume exact dimensions, don't guess boundaries
□ Validate shape constraints (square: w==h, circle: odd width)
```

### 🎯 Detection Priority Order

```
1. Explicit markers (#0#, delimiters)
2. Empty/blank lines
3. Mixed content (spaces + chars) → Circles, complex shapes
4. Pure content starting simple → Triangles (len=1)
5. Pure content any width → Squares
6. Unknown → Skip single line only
```

### 📊 Shape Detection Matrix

| If line has... | And... | Then check... | Extract... |
|----------------|--------|---------------|------------|
| Spaces + stars | Odd width | Circle | r = (width-1)/2 |
| Pure stars | len=1, next=2,3... | Triangle | height = n |
| Pure stars | len=n, n lines | Square | size = n |

### 🔧 Code Template

```python
def parse_encoding(lines):
    i = 0
    while i < len(lines):
        # 1. Markers
        if is_marker(lines[i]):
            handle_marker()
            i += 1
            continue
        
        # 2. Blanks
        if not lines[i].strip():
            i += 1
            continue
        
        # 3. Specific (mixed content)
        if has_spaces_and_chars(lines[i]):
            w = len(lines[i])
            if w % 2 == 1:  # Circle
                # Collect w lines with width w
                r = (w - 1) // 2
                i += w
                continue
        
        # 4. Generic (pure content)
        if is_pure_chars(lines[i]):
            if len(lines[i]) == 1:  # Triangle
                # Collect 1,2,3...n pattern
                i += height
                continue
            else:  # Square
                n = len(lines[i])
                # Verify n lines of length n
                i += n
                continue
        
        i += 1
```

### 💡 Remember

- **Whitespace IS data** - `len(line)` includes spaces
- **Math beats patterns** - Use formulas, not lookup tables
- **Specific beats generic** - Check mixed content before pure
- **Exact beats guess** - Use dimensions, don't look ahead
- **Simple beats complex** - If code is hard, approach is wrong

---

**See full analysis:** `encoding-parsing-traps.md`
