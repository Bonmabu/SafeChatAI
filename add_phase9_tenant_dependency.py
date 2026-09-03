from pathlib import Path

path = Path(r".\main.py")
text = path.read_text(encoding="utf-8")

old = '''def require_customer_access(
    user=Depends(get_current_user)
):
    return _require_roles(
        user,
        {"admin", "customer"}
    )


def require_executive_access(
'''

new = '''def require_customer_access(
    user=Depends(get_current_user)
):
    return _require_roles(
        user,
        {"admin", "customer"}
    )


def get_customer_tenant(
    user=Depends(require_customer_access)
):
    tenant_id = user.get("tenant_id")

    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail="No tenant is assigned to this account."
        )

    return str(tenant_id)


def require_executive_access(
'''

if old not in text:
    raise SystemExit(
        "STOP: Could not find the expected RBAC dependency block."
    )

text = text.replace(old, new, 1)

path.write_text(
    text,
    encoding="utf-8",
    newline="\n"
)

print("Added authenticated customer tenant dependency.")
