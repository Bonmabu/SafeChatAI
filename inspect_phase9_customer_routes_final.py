from pathlib import Path

path = Path(r".\main.py")
lines = path.read_text(encoding="utf-8").splitlines()

for start, end in [
    (4850, 4915),
    (5070, 5220),
    (6570, 6645),
]:
    print()
    print("=" * 80)
    print(f"LINES {start}-{end}")
    print("=" * 80)

    for n in range(start, min(end, len(lines)) + 1):
        print(f"{n:5}: {lines[n-1]}")
