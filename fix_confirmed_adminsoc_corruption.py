from pathlib import Path

path = Path("frontend/src/AdminSOC.jsx")
text = path.read_text(encoding="utf-8")

replacements = {
    "\U0001F6E1\uFE0F\u008FSafeChat AISOC Command Center":
        "\U0001F6E1\uFE0F SafeChat AI SOC Command Center",

    "\U0001F510\u0090":
        "\U0001F510",

    "\U0001F6E1\uFE0F\u008F":
        "\U0001F6E1\uFE0F",

    "\u2699\uFE0F\u008F":
        "\u2699\uFE0F",
}

total = 0

for old, new in replacements.items():
    count = text.count(old)
    if count:
        text = text.replace(old, new)
        total += count
        print(f"Fixed {count} occurrence(s)")

path.write_text(text, encoding="utf-8", newline="\n")
print(f"Total confirmed repairs: {total}")
