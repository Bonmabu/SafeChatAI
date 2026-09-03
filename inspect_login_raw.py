from pathlib import Path

p = Path(r".\main.py")
lines = p.read_text(encoding="utf-8").splitlines()

for i in range(2232, 2281):
    if i <= len(lines):
        print(f"{i+1:5}: {lines[i]!r}")
