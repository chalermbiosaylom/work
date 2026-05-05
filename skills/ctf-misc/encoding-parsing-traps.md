# Encoding & Parsing Challenge Anti-Patterns

## Case Study: ShapesofYou Challenge (RTAF COC 2026)

### Challenge Summary
- **Type:** Encoding/Parsing (Misc)
- **Mechanism:** Octal digits encoded as ASCII art shapes (triangles, squares, circles)
- **Flag:** `flag{c0d1ng_f0r_3z_t4sk_67549890ad}`

### AI Failure Patterns & Traps

#### 🚨 TRAP 1: Character Count vs Line Dimensions
**AI Mistake:**
```python
# ❌ WRONG: Counting visible characters only
stars = line.count('*')
if stars == 1:
    detect_triangle()
```

**Reality:**
```python
# ✅ CORRECT: Check line WIDTH including whitespace
width = len(line)  # Includes spaces!
if '*' in line and ' ' in line:
    # This is a circle (has spaces)
    if width % 2 == 1:  # Odd width
        radius = (width - 1) // 2
```

**Lesson:** Whitespace is DATA, not noise. Line dimensions matter more than character counts.

---

#### 🚨 TRAP 2: Pattern Matching vs Geometric Properties
**AI Mistake:**
```python
# ❌ WRONG: Hardcoded pattern arrays
circle_patterns = {
    1: [1, 3, 1],           # Star counts per line
    2: [1, 3, 5, 3, 1],
    3: [1, 5, 5, 7, 5, 5, 1],
    # ... complex pattern matching
}
```

**Reality:**
```python
# ✅ CORRECT: Simple geometric rules
# Circle: width == height == (2*radius + 1)
w = len(lines[i])
if w % 2 == 1:  # Must be odd
    # Collect w lines with same width w
    if len(block) == w:
        radius = (w - 1) // 2
```

**Lesson:** Use mathematical properties, not pattern databases. Simpler is better.

---

#### 🚨 TRAP 3: Detection Order Matters
**AI Mistake:**
```python
# ❌ WRONG: Check triangles first
if line.count('*') == 1:
    detect_triangle()  # False positive on circles!
elif has_spaces:
    detect_circle()
```

**Reality:**
```python
# ✅ CORRECT: Check most specific patterns first
# Circles have spaces (more specific)
if '*' in line and ' ' in line:
    detect_circle()
# Pure star patterns (less specific)
elif set(line) <= {'*'}:
    if len(line) == 1:
        detect_triangle()
    else:
        detect_square()
```

**Lesson:** Detect specific patterns before generic ones. Circles and triangles can both start with "1 star" but circles have spaces.

---

#### 🚨 TRAP 4: Shape Boundary Detection
**AI Mistake:**
```python
# ❌ WRONG: Looking ahead to find boundaries
while i < len(lines):
    # Collect all lines until empty line or pattern change
    shape_lines = []
    while lines[i] and lines[i] != '#0#':
        shape_lines.append(lines[i])
        i += 1
    # Now try to figure out what shape this is...
```

**Reality:**
```python
# ✅ CORRECT: Use shape geometry to consume exact lines
# Triangle: consume exactly n lines (1,2,3...n stars)
if len(line) == 1:  # Starts with 1 star
    height = 1
    while lines[i+height] has (height+1) stars:
        height += 1
    # Consume exactly 'height' lines
    i += height

# Square: consume exactly n lines of n stars
# Circle: consume exactly (2r+1) lines with width (2r+1)
```

**Lesson:** Don't guess boundaries. Use shape properties to know exactly how many lines to consume.

---

#### 🚨 TRAP 5: Square Dimension Validation
**AI Mistake:**
```python
# ❌ WRONG: Check only that lines have same star count
first_stars = line.count('*')
height = 0
while lines[i].count('*') == first_stars:
    height += 1
# Accept any height > 1
if height > 1:
    digit = first_stars  # WRONG!
```

**Reality:**
```python
# ✅ CORRECT: Square must be n×n (height == width)
L = len(lines[i])  # Line length (should be n)
# Verify exactly L lines, each with length L
for k in range(L):
    if len(lines[i+k]) != L or set(lines[i+k]) != {'*'}:
        not_a_square
# Square size = L (both dimensions match)
```

**Lesson:** Squares are n×n, not "n stars repeated multiple times". Validate both dimensions.

---

### General Anti-Pattern Rules for Encoding Challenges

#### ✅ DO:
1. **Check line characteristics BEFORE content**
   - `len(line)` (width including spaces)
   - `set(line)` (what characters are present)
   - Then check counts/patterns

2. **Use geometric/mathematical properties**
   - Formulas: `r = (w-1)/2`, `area = w*h`
   - Ratios: `width == height` for squares/circles
   - Not hardcoded lookup tables

3. **Detect specific before generic**
   - Mixed content (spaces+chars) before pure content
   - Complex patterns before simple patterns
   - Known delimiters (`#0#`) first

4. **Consume exact dimensions**
   - Know how many lines a shape needs
   - Don't look ahead for "end of shape"
   - Use shape properties to advance pointer

5. **Handle whitespace as data**
   - Trailing spaces matter
   - Leading spaces matter
   - Empty lines are signals

#### ❌ DON'T:
1. **Don't ignore whitespace**
   - `line.strip()` loses information
   - `line.count('*')` ignores spaces
   - Use `len(line)` for true width

2. **Don't hardcode patterns**
   - Avoid lookup tables for geometric shapes
   - Use math formulas instead
   - Patterns are brittle and incomplete

3. **Don't guess boundaries**
   - No "read until empty line"
   - No "read until pattern changes"
   - Use exact dimensions from shape type

4. **Don't check generic patterns first**
   - Triangles (1 star) before circles (1 star + spaces) = WRONG
   - Check most specific/constrained patterns first

5. **Don't over-engineer**
   - Complex pattern matching usually wrong
   - Simple geometric rules usually right
   - If code is complex, rethink approach

---

### Detection Priority Template

```python
def parse_ascii_art_encoding(lines):
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # 1. Check explicit markers first
        if line.strip() == "#0#":
            handle_zero()
            i += 1
            continue
        
        # 2. Skip truly empty lines
        if not line.strip():
            i += 1
            continue
        
        # 3. Check SPECIFIC patterns (mixed content)
        if has_mixed_content(line):  # e.g., spaces + stars
            if detect_circle(lines, i):
                i += circle_height
                continue
        
        # 4. Check GENERIC patterns (pure content)
        if is_pure_stars(line):
            if len(line) == 1:
                # Could be triangle
                if detect_triangle(lines, i):
                    i += triangle_height
                    continue
            else:
                # Could be square
                if detect_square(lines, i):
                    i += square_height
                    continue
        
        # 5. Unknown - skip single line
        i += 1
```

---

### Key Insights

**Why AI fails at these challenges:**
1. **Focuses on visible content** (stars) over structure (width, spaces)
2. **Uses pattern matching** instead of geometric reasoning
3. **Ignores whitespace** as "formatting" not "data"
4. **Over-complicates** with lookup tables and complex logic
5. **Checks generic before specific** causing false positives

**How to succeed:**
1. Think **geometrically** (dimensions, ratios, formulas)
2. Treat **whitespace as data** (width includes spaces)
3. Use **simple math** over complex patterns
4. Detect **specific before generic** (mixed before pure)
5. **Consume exact dimensions** (don't guess boundaries)

---

### Quick Reference: Shape Detection

| Shape | Line Property | Width | Height | Detection |
|-------|---------------|-------|--------|-----------|
| Triangle | Pure `*` | Increasing 1→n | n | `len(line) == star_count`, starts at 1 |
| Square | Pure `*` | Constant n | n | `len(line) == n`, exactly n lines |
| Circle | Mixed `* ` | Odd, constant | = width | `len(line)` odd, has spaces, height==width |

**Priority:** Circle (specific) → Triangle (starts at 1) → Square (any width)
