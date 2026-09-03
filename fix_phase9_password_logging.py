from pathlib import Path

path = Path(r".\main.py")
text = path.read_text(encoding="utf-8")

old = '    print("LOGIN PASSWORD:", repr(request.password), flush=True)\n'

if old not in text:
    print("Password logging line not found.")
else:
    text = text.replace(old, "")
    path.write_text(text, encoding="utf-8", newline="\n")
    print("Removed plaintext password logging from /login.")
