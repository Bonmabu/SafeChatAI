from pathlib import Path

path = Path(r".\main.py")
text = path.read_text(encoding="utf-8")

replacements = {
    'def customer_dashboard(tenant_id: str = "demo"):':
    'def customer_dashboard(tenant_id: str = Depends(get_customer_tenant)):',

    'def customer_attack_trend(tenant_id: str):':
    'def customer_attack_trend(tenant_id: str = Depends(get_customer_tenant)):',

    'def customer_incidents(tenant_id: str):':
    'def customer_incidents(tenant_id: str = Depends(get_customer_tenant)):',

    'def customer_trends(tenant_id: str = "demo"):':
    'def customer_trends(tenant_id: str = Depends(get_customer_tenant)):',

    'def customer_categories(tenant_id: str = "demo"):':
    'def customer_categories(tenant_id: str = Depends(get_customer_tenant)):',

    'def customer_status(tenant_id: str = "demo"):':
    'def customer_status(tenant_id: str = Depends(get_customer_tenant)):',

    'def customer_alerts(tenant_id: str):':
    'def customer_alerts(tenant_id: str = Depends(get_customer_tenant)):',
}

changed = []

for old, new in replacements.items():
    if old not in text:
        print(f"WARNING: Pattern not found: {old}")
        continue

    text = text.replace(old, new, 1)
    changed.append(old)

path.write_text(text, encoding="utf-8", newline="\n")

print(f"Updated {len(changed)} customer tenant-isolation routes.")

for item in changed:
    print(" -", item)
