from pathlib import Path

path = Path(r".\main.py")
text = path.read_text(encoding="utf-8")

old = '''        tenant_id = payload.get("tenant_id", "demo")

        return {
            "username": username,
            "role": role,
            "tenant_id": tenant_id
        }
'''

new = '''        tenant_id = payload.get("tenant_id", "demo")

        # --------------------------------------------------------
        # ADMIN ACCOUNT STATUS ENFORCEMENT
        # --------------------------------------------------------
        conn = get_conn()
        cursor = conn.cursor()

        try:
            cursor.execute(
                db_sql("""
                    SELECT
                        id,
                        username,
                        role,
                        tenant_id,
                        status,
                        is_active,
                        session_version
                    FROM users
                    WHERE username = ?
                    LIMIT 1
                """),
                (username,)
            )

            db_user = cursor.fetchone()

        finally:
            conn.close()

        if db_user:
            account_status = str(
                db_user["status"] or "active"
            ).lower()

            is_active = db_user["is_active"]

            if account_status in ("blocked", "suspended") or is_active in (0, False):
                raise HTTPException(
                    status_code=403,
                    detail="User account is suspended or blocked."
                )

            token_session_version = payload.get(
                "session_version",
                db_user["session_version"] or 0
            )

            if int(token_session_version) != int(
                db_user["session_version"] or 0
            ):
                raise HTTPException(
                    status_code=401,
                    detail="Session has been revoked. Please sign in again."
                )

            tenant_id = db_user["tenant_id"] or tenant_id
            role = db_user["role"] or role

        return {
            "id": db_user["id"] if db_user else None,
            "username": username,
            "role": role,
            "tenant_id": tenant_id
        }
'''

if old not in text:
    raise SystemExit("Could not find get_current_user return block.")

text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8", newline="\n")

print("JWT account-status enforcement installed.")


