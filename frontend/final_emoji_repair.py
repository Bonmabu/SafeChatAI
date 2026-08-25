from pathlib import Path

replacements = {
    "src/App.jsx": {
        "Ã°Å¸â€Â¥": "🛡️",
        "âWS ERROR": "⚠️ WS ERROR",
        "âœ&#9989;": "✅",
        "Ã°Å¸â€Â": "🔎",
        "â&#10060;": "❌",
    },

    "src/executive/ExecutiveDashboard.jsx": {
        "ðŸŒÂ": "🌐",
        "â—Â": "●",
        "Ã°Å¸Ââ€ ": "🛡️",
        "ðŸ–": "🖖",
        "Ã¢ÂÂ¸": "⏸",
        "ðŸŒÅ½": "🌎",
    },
}

for filename, mapping in replacements.items():
    path = Path(filename)

    text = path.read_text(encoding="utf-8")
    before = text

    for bad, good in mapping.items():
        text = text.replace(bad, good)

    path.write_text(text, encoding="utf-8", newline="\n")

    count = sum(before.count(bad) for bad in mapping)
    print(f"{filename}: replaced {count} corrupted occurrence(s)")

print("Final targeted emoji repair completed.")
