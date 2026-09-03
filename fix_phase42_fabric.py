from pathlib import Path

path = Path(".\main.py")
text = path.read_text(encoding="utf-8")

old = '''    validate_event(event)

    # -------------------------
    # EVENT ROUTING MAP
    # -------------------------'''

new = '''    validate_event(event)

    # -------------------------
    # SECURITY DATA FABRIC
    # -------------------------
    persist_security_event(event)

    # -------------------------
    # EVENT ROUTING MAP
    # -------------------------'''

if old not in text:
    raise SystemExit("Target block not found. No changes made.")

text = text.replace(old, new, 1)
path.write_text(text, encoding="utf-8")

print("Phase 42 integration fixed: push_event now persists events to Security Data Fabric.")
