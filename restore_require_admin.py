from pathlib import Path

path = Path("main.py")
text = path.read_text(encoding="utf-8")

marker = 'def build_executive_payload():'

if "def require_admin(" in text:
    print("require_admin already exists. No changes made.")
    raise SystemExit(0)

pos = text.find(marker)

if pos < 0:
    raise SystemExit(
        "ERROR: build_executive_payload marker not found. main.py NOT changed."
    )

helper = '''def require_admin(user=Depends(get_current_user)):
    """
    Require an authenticated administrator for admin-only endpoints.
    Uses the existing get_current_user authentication dependency.
    """
    role = None

    if isinstance(user, dict):
        role = user.get("role")
    else:
        role = getattr(user, "role", None)

    if str(role or "").strip().lower() != "admin":
        raise HTTPException(
            status_code=403,
            detail="Administrator privileges required."
        )

    return user


'''

text = text[:pos] + helper + text[pos:]

path.write_text(text, encoding="utf-8", newline="\n")

print("SUCCESS: require_admin dependency restored.")
