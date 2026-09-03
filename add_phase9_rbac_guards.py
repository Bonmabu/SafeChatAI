from pathlib import Path

path = Path(r".\main.py")
text = path.read_text(encoding="utf-8")

marker = "\ndef background_siem_processor():"

if "def require_customer_access(" in text:
    print("RBAC guards already exist. No change made.")
elif marker not in text:
    raise SystemExit("Could not find insertion point. No changes made.")
else:
    block = r'''
def _require_roles(user, allowed_roles):
    role = str(user.get("role", "")).lower()

    if role not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions for this resource."
        )

    return user


def require_customer_access(
    user=Depends(get_current_user)
):
    return _require_roles(
        user,
        {"admin", "customer"}
    )


def require_executive_access(
    user=Depends(get_current_user)
):
    return _require_roles(
        user,
        {"admin", "executive"}
    )


'''
    text = text.replace(marker, "\n" + block + "def background_siem_processor():", 1)
    path.write_text(text, encoding="utf-8", newline="\n")
    print("Added customer/executive backend RBAC guards.")
