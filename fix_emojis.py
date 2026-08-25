from pathlib import Path

p = Path("frontend/src/executive/ExecutiveDashboard.jsx")
text = p.read_text(encoding="utf-8-sig")

# Mojibake markers represented by Unicode code points.
bad_markers = [
    "\u00f0\u0178",
    "\u00e2\u0161",
    "\u00e2\u20ac",
]

lines = text.splitlines(True)
out = []
fixed = 0

for line in lines:
    if any(marker in line for marker in bad_markers):
        try:
            line = line.encode("latin1").decode("utf-8")
            fixed += 1
        except UnicodeError:
            pass
    out.append(line)

p.write_text("".join(out), encoding="utf-8")

print(f"Repaired corrupted lines: {fixed}")
