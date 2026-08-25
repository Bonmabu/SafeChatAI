from pathlib import Path
import re

path = Path("main.py")
text = path.read_text(encoding="utf-8")

pattern = r'''cursor\.execute\("""\s*SELECT.*?FROM users\s*ORDER BY created_at DESC'''

replacement = '''cursor.execute("""
        SELECT
            id,
            username,
            full_name,
            email,
            role,
            tenant_id,
            created_at,
            status,
            is_active,
            password_reset_required,
            suspended_at,
            blocked_at,
            mfa_enabled
        FROM users
        ORDER BY created_at DESC'''

match = re.search(pattern, text, flags=re.DOTALL)

if not match:
    raise SystemExit(
        "ERROR: executive_users SELECT block not found. main.py NOT changed."
    )

new_text = text[:match.start()] + replacement + text[match.end():]

path.write_text(new_text, encoding="utf-8", newline="\n")

print("SUCCESS: executive_users SELECT block fixed.")
