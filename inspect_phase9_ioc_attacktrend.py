from pathlib import Path

path = Path(r".\main.py")
lines = path.read_text(encoding="utf-8").splitlines()

for start, end in [
    (5078, 5105),
    (6637, 6685),
]:
    print()
    print("=" * 80)
    print(f"LINES {start}-{end}")
    print("=" * 80)

    for n in range(start, min(end, len(lines)) + 1):
        print(f"{n:5}: {lines[n-1]}")
