from pathlib import Path

p = Path(r".\main.py")
t = p.read_text(encoding="utf-8")

replacements = {
    279: "🔐 PHASE 9 AUTH SYSTEM",
    354: "❌ SEND FAILED:",
    1345: "🔴 CRITICAL THREAT",
    2102: "⚠️ too many threats ⚠️ increase sensitivity",
    3096: "🔎 ANALYZE ENDPOINT HIT",
    3804: "🧪 ADD THIS TEST NODE",
    3852: "🛡️ ENTERPRISE SOC SIEM",
    4646: "🤖 SOC-AI-STREAM ENDPOINT HIT",
    5140: "🔌 /ws/soc CONNECTED",
}

lines = t.splitlines()

for line_no, replacement in replacements.items():
    old = lines[line_no - 1]

    if line_no == 279:
        lines[line_no - 1] = "# " + replacement
    elif line_no == 354:
        lines[line_no - 1] = '                print("' + replacement + '", e)'
    elif line_no == 1345:
        lines[line_no - 1] = "    # " + replacement
    elif line_no == 2102:
        lines[line_no - 1] = "    # " + replacement
    elif line_no == 3096:
        lines[line_no - 1] = '    print("' + replacement + '")'
    elif line_no == 3804:
        lines[line_no - 1] = "    # " + replacement
    elif line_no == 3852:
        lines[line_no - 1] = "        <h1>" + replacement + "</h1>"
    elif line_no == 4646:
        lines[line_no - 1] = '    print("' + replacement + '")'
    elif line_no == 5140:
        lines[line_no - 1] = '    print("' + replacement + '")'

p.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
print("FIXED 9 CONFIRMED MOJIBAKE LINES")
