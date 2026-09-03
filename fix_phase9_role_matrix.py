from pathlib import Path

path = Path(r".\main.py")
text = path.read_text(encoding="utf-8")

old = '''USER_ROLES = {
    "admin": ["read", "write", "delete", "analyze"],
    "analyst": ["read", "analyze"],
    "viewer": ["read"]
}'''

new = '''USER_ROLES = {
    "admin": ["read", "write", "delete", "analyze"],
    "analyst": ["read", "analyze"],
    "viewer": ["read"],
    "customer": ["read", "analyze"],
    "executive": ["read", "analyze"]
}'''

if old not in text:
    print("Expected USER_ROLES block not found. No change made.")
else:
    text = text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8", newline="\n")
    print("Updated USER_ROLES for customer and executive roles.")
