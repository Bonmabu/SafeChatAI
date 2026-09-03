from pathlib import Path

ROOTS = [
    Path(r".\main.py"),
    Path(r".\db.py"),
    Path(r".\engine.py"),
    Path(r".\security_fabric.py"),
    Path(r".\ml_model.py"),
    Path(r".\ai"),
    Path(r".\frontend\src"),
]

EXTENSIONS = {".py", ".jsx", ".js", ".tsx", ".ts", ".css", ".html", ".json"}

BAD = ("Ã", "Â", "â", "ð", "�", "œ", "™", "š", "ž")

def repair(text):
    for _ in range(3):
        if not any(x in text for x in BAD):
            break
        try:
            fixed = text.encode("latin1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            break
        if fixed == text:
            break
        text = fixed
    return text

changed = 0

for root in ROOTS:
    paths = [root] if root.is_file() else (
        root.rglob("*") if root.exists() else []
    )

    for path in paths:
        if not path.is_file() or path.suffix.lower() not in EXTENSIONS:
            continue

        try:
            text = path.read_text(encoding="utf-8")
            fixed = repair(text)

            if fixed != text:
                path.write_text(fixed, encoding="utf-8", newline="\n")
                changed += 1
                print(f"REPAIRED: {path}")
        except (UnicodeDecodeError, OSError):
            pass

print(f"\nFiles repaired: {changed}")

