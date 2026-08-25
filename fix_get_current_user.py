from pathlib import Path

path = Path(".\main.py")
text = path.read_text(encoding="utf-8")

start = text.index("def get_current_user(")
end = text.index("def verify_token(", start)

new_function = '''def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        username = payload.get("sub")
        role = payload.get("role")

        if username is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid token"
            )

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
            db_user = dict(db_user)

            status = str(
                db_user.get("status") or "active"
            ).lower()

            if status in ("blocked", "suspended") or not db_user.get("is_active", 1):
                raise HTTPException(
                    status_code=403,
                    detail="User account is suspended or blocked."
                )

            token_version = int(
                payload.get("session_version", 0)
            )

            db_version = int(
                db_user.get("session_version") or 0
            )

            if token_version != db_version:
                raise HTTPException(
                    status_code=401,
                    detail="Session has been revoked. Please sign in again."
                )

            role = db_user.get("role") or role

            return {
                "id": db_user.get("id"),
                "username": db_user.get("username"),
                "role": role,
                "tenant_id": db_user.get("tenant_id")
            }

        return {
            "id": payload.get("user_id"),
            "username": username,
            "role": role,
            "tenant_id": payload.get("tenant_id", "demo")
        }

    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )


'''

text = text[:start] + new_function + text[end:]

path.write_text(text, encoding="utf-8", newline="\n")

print("get_current_user fixed.")
