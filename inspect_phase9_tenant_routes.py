from pathlib import Path

path = Path(r".\main.py")
lines = path.read_text(encoding="utf-8").splitlines()

ranges = [
    (4848, 4885),
    (5065, 5185),
    (5185, 5215),
    (6565, 6635),
]

for start, end in ranges:
    print()
    print("=" * 70)
    print(f"LINES {start}-{end}")
    print("=" * 70)

    for n in range(start, min(end, len(lines)) + 1):
        print(f"{n:5}: {lines[n-1]}")
