# ShapesofYou Challenge - Lessons Learned (RTAF COC 2026)

**Date:** 2026-03-25  
**Challenge:** ShapesofYou (Misc/Encoding)  
**Flag:** `flag{c0d1ng_f0r_3z_t4sk_67549890ad}`

## Challenge Summary
ASCII art shapes (triangles, squares, circles) encoding octal digits. Each shape represents a digit 0-7, which when decoded from octal reveals the flag.

## AI Failure Analysis

### Critical Mistakes Made

1. **Whitespace Blindness** - Counted `line.count('*')` instead of `len(line)`
2. **Pattern Over-Engineering** - Created hardcoded lookup tables instead of using geometric formulas
3. **Wrong Detection Order** - Checked triangles before circles, causing false positives
4. **Boundary Guessing** - Tried to find shape boundaries by looking ahead
5. **Dimension Validation** - Didn't validate n×n for squares or width==height for circles

### What Worked (Correct Solution)

```python
# Key insights from working solution:
# 1. Check line WIDTH (len(line)) not just star count
# 2. Detect circles (mixed content) BEFORE triangles (pure content)
# 3. Use geometric formulas: radius = (width-1)/2
# 4. Consume exact dimensions based on shape type
# 5. Validate constraints: squares are n×n, circles have width==height
```

## Skills Updated

### 1. ctf-misc
- **Added:** `encoding-parsing-traps.md` - Full case study with 5 trap categories
- **Added:** `ANTI_PATTERN_ENCODING.md` - Quick reference card
- **Updated:** `SKILL.md` - Added references to new anti-pattern docs

### 2. ctf-omni-anti-trap
- **Added:** Section 4 - ASCII Art & Encoding Parsing Traps
- **Added:** Detection priority template
- **Added:** Geometric formula guidelines

## Key Takeaways

### For Future Encoding Challenges:

✅ **DO:**
- Check `len(line)` before `line.count(char)`
- Detect specific patterns (mixed content) before generic (pure content)
- Use math formulas over lookup tables
- Consume exact dimensions, don't guess boundaries
- Validate geometric constraints

❌ **DON'T:**
- Ignore whitespace (it's data, not formatting)
- Hardcode pattern arrays
- Check generic patterns first
- Look ahead to find boundaries
- Skip dimension validation

## Prevention Guidelines

**Detection Priority Order:**
1. Explicit markers (#0#, delimiters)
2. Empty/blank lines
3. Mixed content (spaces + chars) → Circles
4. Pure content, len=1 → Triangles
5. Pure content, any width → Squares

**Geometric Rules:**
- Circle: `radius = (width - 1) / 2`, width must be odd, width == height
- Square: `size = width`, must have exactly `size` lines of `size` stars each
- Triangle: `height = n`, lines have 1,2,3...n stars

## Files Created

1. `/home/kali/Desktop/.windsurf/skills/ctf-misc/encoding-parsing-traps.md`
2. `/home/kali/Desktop/.windsurf/skills/ctf-misc/ANTI_PATTERN_ENCODING.md`
3. `/home/kali/Desktop/CTF/AI_MISTAKES_ANALYSIS.md`
4. `/home/kali/Desktop/CTF/working_solution.py`

## Impact

This challenge revealed a fundamental AI weakness: **focusing on visible content over structure**. The lessons apply to:
- ASCII art encoding challenges
- Steganography with whitespace
- Format parsing with mixed content
- Any challenge where dimensions matter more than character counts

**Status:** ✅ Documented and integrated into skill system
