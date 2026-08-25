from pathlib import Path

path = Path("main.py")
text = path.read_text(encoding="utf-8")
lines = text.splitlines()

replacements = {
    278: '# 🔐 PHASE 9 AUTH SYSTEM',
    351: '                print("❌ SEND FAILED:", e)',
    1337: '    # 🔴 CRITICAL THREAT',
    2020: '    # 🔴 too many threats → increase sensitivity',
    2397: '    print("🔥 ANALYZE ENDPOINT HIT")',
    3055: '    # 🔥 ADD THIS TEST NODE',
    3082: '        <h1>🔥 ENTERPRISE SOC SIEM</h1>',
    3876: '    print("🔥 SOC-AI-STREAM ENDPOINT HIT")',
    4370: '    print("🔥 /ws/soc CONNECTED")',
}

for line_number, replacement in replacements.items():
    index = line_number - 1

    if index >= len(lines):
        raise RuntimeError(f"Line {line_number} does not exist")

    print(f"Fixing line {line_number}")
    lines[index] = replacement

path.write_text(
    "\n".join(lines) + "\n",
    encoding="utf-8",
    newline="\n"
)

print(f"Fixed {len(replacements)} specific mojibake lines.")
