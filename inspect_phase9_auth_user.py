from pathlib import Path

path = Path(r".\main.py")
lines = path.read_text(encoding="utf-8").splitlines()

for n in range(1843, 1932):
    if n <= len(lines):
        print(f"{n:5}: {lines[n-1]}")
