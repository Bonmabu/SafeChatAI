from pathlib import Path

p = Path(r".\frontend\src\ProtectedRoute.jsx")
text = p.read_text(encoding="utf-8")

for i, line in enumerate(text.splitlines(), 1):
    if 20 <= i <= 43:
        print(f"{i:4}: {line!r}")
