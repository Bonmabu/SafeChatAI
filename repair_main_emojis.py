from pathlib import Path

path = Path(r".\main.py")
text = path.read_text(encoding="utf-8")

for i in range(8):
    try:
        repaired = text.encode("cp1252").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        break

    if repaired == text:
        break

    text = repaired
    print(f"Repair pass {i + 1} applied.")

path.write_text(text, encoding="utf-8", newline="\n")

print("main.py emoji/mojibake repair completed.")
