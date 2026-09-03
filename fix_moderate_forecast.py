from pathlib import Path

path = Path("main.py")
text = path.read_text(encoding="utf-8")

old = '''    elif avg >= 50:
        probability = 65
'''

new = '''    elif avg >= 50:
        probability = 65
        forecast = "Moderate threat activity expected."
'''

if old not in text:
    raise SystemExit("ERROR: Expected probability block not found. NO CHANGES MADE.")

text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8", newline="\n")

print("SUCCESS: Moderate forecast logic restored.")
