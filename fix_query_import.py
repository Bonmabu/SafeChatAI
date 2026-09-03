from pathlib import Path

path = Path(".\main.py")
text = path.read_text(encoding="utf-8")

if "Query" not in text.split(")", 1)[0]:
    text = text.replace(
        "from fastapi import Request,",
        "from fastapi import Request, Query,",
        1
    )

path.write_text(text, encoding="utf-8", newline="\n")
print("FastAPI Query import fixed.")
