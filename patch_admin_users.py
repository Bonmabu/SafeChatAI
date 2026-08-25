from pathlib import Path

path = Path(r".\main.py")
text = path.read_text(encoding="utf-8")

marker = '@app.get("/executive-ai")'

block = r'''
# ============================================================
# ADMIN USER MANAGEMENT API
# ============================================================

@app.get("/admin/users")
def admin_users(user=Depends(require_admin)):
    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(db_sql("""
            SELECT
                id,
                username,
                full_name,
                email,
                role,
                tenant_id,
                status,
                is_active,
                suspended_at,
                blocked_at,
                session_version,
                password_reset_required,
                mfa_enabled,
                created_at
            FROM users
            ORDER BY id DESC
        """))

        users = [dict(row) for row in cursor.fetchall()]

        return {
            "success": True,
            "total_users": len(users),
            "users": users
        }

    finally:
        conn.close()


@app.get("/admin/users/{user_id}")
def admin_user_details(
    user_id: int,
    user=Depends(require_admin)
):
    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(db_sql("""
            SELECT
                id,
                username,
                full_name,
                email,
                role,
                tenant_id,
                status,
                is_active,
                suspended_at,
                blocked_at,
                session_version,
                password_reset_required,
                mfa_enabled,
                created_at
            FROM users
            WHERE id = ?
        """), (user_id,))

        target = cursor.fetchone()

        if not target:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        return {
            "success": True,
            "user": dict(target)
        }

    finally:
        conn.close()


@app.patch("/admin/users/{user_id}/status")
def admin_change_user_status(
    user_id: int,
    status: str,
    user=Depends(require_admin)
):
    status = status.strip().lower()

    allowed = {
        "active",
        "suspended",
        "blocked"
    }

    if status not in allowed:
        raise HTTPException(
            status_code=400,
            detail="Status must be active, suspended, or blocked."
        )

    if user.get("id") == user_id and status != "active":
        raise HTTPException(
            status_code=400,
            detail="An administrator cannot suspend or block their own account."
        )

    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            db_sql("""
                SELECT id, username
                FROM users
                WHERE id = ?
            """),
            (user_id,)
        )

        target = cursor.fetchone()

        if not target:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        now = datetime.utcnow().isoformat()

        if status == "active":
            cursor.execute(
                db_sql("""
                    UPDATE users
                    SET status = 'active',
                        is_active = 1,
                        suspended_at = NULL,
                        blocked_at = NULL,
                        session_version = COALESCE(session_version, 0) + 1
                    WHERE id = ?
                """),
                (user_id,)
            )

        elif status == "suspended":
            cursor.execute(
                db_sql("""
                    UPDATE users
                    SET status = 'suspended',
                        is_active = 0,
                        suspended_at = ?,
                        session_version = COALESCE(session_version, 0) + 1
                    WHERE id = ?
                """),
                (now, user_id)
            )

        else:
            cursor.execute(
                db_sql("""
                    UPDATE users
                    SET status = 'blocked',
                        is_active = 0,
                        blocked_at = ?,
                        session_version = COALESCE(session_version, 0) + 1
                    WHERE id = ?
                """),
                (now, user_id)
            )

        conn.commit()

        try:
            create_audit_log(
                action=f"USER_STATUS_CHANGE:{status}",
                user=user.get("username"),
                message=f"Admin changed user {target['username']} to {status}"
            )
        except Exception:
            pass

        return {
            "success": True,
            "user_id": user_id,
            "status": status
        }

    finally:
        conn.close()


@app.post("/admin/users/{user_id}/force-logout")
def admin_force_logout(
    user_id: int,
    user=Depends(require_admin)
):
    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            db_sql("""
                SELECT username
                FROM users
                WHERE id = ?
            """),
            (user_id,)
        )

        target = cursor.fetchone()

        if not target:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        cursor.execute(
            db_sql("""
                UPDATE users
                SET session_version = COALESCE(session_version, 0) + 1
                WHERE id = ?
            """),
            (user_id,)
        )

        conn.commit()

        try:
            create_audit_log(
                action="FORCE_LOGOUT",
                user=user.get("username"),
                message=f"Admin revoked all sessions for {target['username']}"
            )
        except Exception:
            pass

        return {
            "success": True,
            "message": "All user sessions have been revoked."
        }

    finally:
        conn.close()


@app.patch("/admin/users/{user_id}/role")
def admin_change_user_role(
    user_id: int,
    role: str,
    user=Depends(require_admin)
):
    role = role.strip().lower()

    allowed = {
        "admin",
        "analyst",
        "viewer",
        "customer",
        "executive"
    }

    if role not in allowed:
        raise HTTPException(
            status_code=400,
            detail="Invalid role."
        )

    if user.get("id") == user_id and role != "admin":
        raise HTTPException(
            status_code=400,
            detail="An administrator cannot remove their own administrator role."
        )

    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            db_sql("""
                UPDATE users
                SET role = ?,
                    session_version = COALESCE(session_version, 0) + 1
                WHERE id = ?
            """),
            (role, user_id)
        )

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        conn.commit()

        return {
            "success": True,
            "user_id": user_id,
            "role": role
        }

    finally:
        conn.close()


@app.patch("/admin/users/{user_id}/tenant")
def admin_change_user_tenant(
    user_id: int,
    tenant_id: str,
    user=Depends(require_admin)
):
    tenant_id = tenant_id.strip()

    if not tenant_id:
        raise HTTPException(
            status_code=400,
            detail="Tenant ID is required."
        )

    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            db_sql("""
                UPDATE users
                SET tenant_id = ?,
                    session_version = COALESCE(session_version, 0) + 1
                WHERE id = ?
            """),
            (tenant_id, user_id)
        )

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        conn.commit()

        return {
            "success": True,
            "user_id": user_id,
            "tenant_id": tenant_id
        }

    finally:
        conn.close()


@app.post("/admin/users/{user_id}/password-reset")
def admin_password_reset(
    user_id: int,
    user=Depends(require_admin)
):
    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            db_sql("""
                SELECT id, username, email
                FROM users
                WHERE id = ?
            """),
            (user_id,)
        )

        target = cursor.fetchone()

        if not target:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        reset_token = secrets.token_urlsafe(48)
        expires_at = datetime.utcnow() + timedelta(minutes=30)

        cursor.execute(
            db_sql("""
                UPDATE users
                SET reset_token = ?,
                    reset_token_expires = ?,
                    password_reset_required = 1
                WHERE id = ?
            """),
            (
                reset_token,
                expires_at.isoformat(),
                user_id
            )
        )

        conn.commit()

        try:
            create_audit_log(
                action="ADMIN_PASSWORD_RESET",
                user=user.get("username"),
                message=f"Password reset initiated for {target['username']}"
            )
        except Exception:
            pass

        return {
            "success": True,
            "message": "Password reset token generated.",
            "username": target["username"],
            "expires_at": expires_at.isoformat(),
            "reset_token": reset_token
        }

    finally:
        conn.close()


@app.post("/admin/users/{user_id}/mfa-reset")
def admin_mfa_reset(
    user_id: int,
    user=Depends(require_admin)
):
    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            db_sql("""
                UPDATE users
                SET mfa_enabled = 0,
                    session_version = COALESCE(session_version, 0) + 1
                WHERE id = ?
            """),
            (user_id,)
        )

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        conn.commit()

        return {
            "success": True,
            "message": "MFA has been reset and existing sessions revoked."
        }

    finally:
        conn.close()


@app.delete("/admin/users/{user_id}")
def admin_delete_user(
    user_id: int,
    user=Depends(require_admin)
):
    if user.get("id") == user_id:
        raise HTTPException(
            status_code=400,
            detail="An administrator cannot delete their own account."
        )

    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            db_sql("""
                SELECT username
                FROM users
                WHERE id = ?
            """),
            (user_id,)
        )

        target = cursor.fetchone()

        if not target:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        cursor.execute(
            db_sql("""
                DELETE FROM users
                WHERE id = ?
            """),
            (user_id,)
        )

        conn.commit()

        try:
            create_audit_log(
                action="USER_DELETED",
                user=user.get("username"),
                message=f"Admin deleted user {target['username']}"
            )
        except Exception:
            pass

        return {
            "success": True,
            "message": "User account deleted."
        }

    finally:
        conn.close()


'''

if "def admin_change_user_status(" in text:
    raise SystemExit("Admin user-management API already exists.")

if marker not in text:
    raise SystemExit("Could not find executive-ai insertion marker.")

text = text.replace(marker, block + marker, 1)

path.write_text(text, encoding="utf-8", newline="\n")

print("Admin User Management API installed.")

