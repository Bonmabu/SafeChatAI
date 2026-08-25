from pathlib import Path

path = Path(r".\frontend\src\AdminSOC.jsx")

text = path.read_text(encoding="utf-8-sig")

passes = 0

while True:
    try:
        fixed = text.encode("latin1").decode("utf-8")
    except UnicodeError:
        break

    if fixed == text:
        break

    text = fixed
    passes += 1

    if passes >= 3:
        break

path.write_text(text, encoding="utf-8", newline="\n")

print(f"Emoji encoding repair completed: {passes} pass(es)")
