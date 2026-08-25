from pathlib import Path

path = Path("frontend/src/executive/ExecutiveDashboard.jsx")
text = path.read_text(encoding="utf-8")

replacements = {
    "ðŸ§  ": "",
    "ðŸ† ": "",
    "ðŸ“‹ ": "",
    "ðŸ” ": "",
    "ðŸ”® ": "",
    "âš¡ ": "",
    "ðŸ“Š ": "",
    "ðŸŽ– ": "",
    "ðŸ“ˆ ": "",
    "ðŸŽ¯ ": "",
    "ðŸŽ¬ ": "",
    "â–¶ ": "",
    "â¸ ": "",
    "âŸ² ": "",
}

for old, new in replacements.items():
    text = text.replace(old, new)

path.write_text(text, encoding="utf-8", newline="\n")

print("Removed remaining ExecutiveDashboard mojibake prefixes.")
