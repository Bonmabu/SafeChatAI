from pathlib import Path

path = Path(".\main.py")
text = path.read_text(encoding="utf-8")

text = text.replace(
    "from fastapi import Request, (",
    "from fastapi import ("
)

path.write_text(text, encoding="utf-8", newline="\n")
print("Fixed FastAPI import.")
