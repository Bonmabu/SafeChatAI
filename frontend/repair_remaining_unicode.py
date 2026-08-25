from pathlib import Path

def u(*codes):
    return "".join(chr(c) for c in codes)

files = {
    "src/App.jsx": {
        "ADD THIS (important)": u(0x1F6E1, 0xFE0F) + " ADD THIS (important)",
        "Investigate": u(0x1F50E) + " Investigate",
    },

    "src/executive/ExecutiveDashboard.jsx": {
        "Live Attack Network": u(0x1F310) + " Live Attack Network",
        "LIVE": u(0x25CF) + " LIVE",
        "Security Maturity Scorecard": u(0x1F6E1, 0xFE0F) + " Security Maturity Scorecard",
        "Incident Commander": u(0x1F5D6) + " Incident Commander",
        "Live Threat Feed": u(0x1F310) + " Live Threat Feed",
        "Live Executive Attack Graph": u(0x1F310) + " Live Executive Attack Graph",
        "Pause": u(0x23F8, 0xFE0F) + " Pause",
        "Global Threat Intelligence": u(0x1F310) + " Global Threat Intelligence",
        "{item.country}": u(0x1F310) + " {item.country}",
        "Country Intelligence": u(0x1F30E) + " Country Intelligence",
    },
}

for filename, targets in files.items():
    path = Path(filename)
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    changed = 0

    for i, line in enumerate(lines):
        stripped = line.strip()

        for target, replacement in targets.items():

            if target == "LIVE":
                if stripped.endswith("LIVE") and ("LIVE" in stripped):
                    indent = line[:len(line) - len(line.lstrip())]
                    lines[i] = indent + replacement + "\n"
                    changed += 1
                    break

            elif target == "Investigate":
                if "Investigate" in line:
                    prefix = line[:line.index("Investigate")]
                    lines[i] = prefix + replacement + "\n"
                    changed += 1
                    break

            elif target == "ADD THIS (important)":
                if "ADD THIS (important)" in line:
                    indent = line[:len(line) - len(line.lstrip())]
                    lines[i] = indent + "return;   // " + replacement + "\n"
                    changed += 1
                    break

            elif target == "{item.country}":
                if "{item.country}" in line:
                    indent = line[:len(line) - len(line.lstrip())]
                    lines[i] = indent + replacement + "\n"
                    changed += 1
                    break

            elif target in line:
                # Preserve indentation and JSX structure.
                indent = line[:len(line) - len(line.lstrip())]

                if line.lstrip().startswith("<h2>"):
                    lines[i] = indent + "<h2>" + replacement + "</h2>\n"
                else:
                    lines[i] = indent + replacement + "\n"

                changed += 1
                break

    path.write_text("".join(lines), encoding="utf-8", newline="\n")
    print(f"{filename}: fixed {changed} line(s)")

print("Unicode repair completed.")
