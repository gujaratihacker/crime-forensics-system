import functools
import pymysql
from flask import session, redirect, url_for, flash, abort, g
from config import Config

def get_db_connection():
    """Establish a connection to the database, returning a dictionary cursor."""
    try:
        return pymysql.connect(
            host=Config.DB_HOST,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            database=Config.DB_NAME,
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True
        )
    except (pymysql.MySQLError, OSError, ValueError) as exc:
        import sys
        print(f"DB connection failed: {exc}", file=sys.stderr)
        raise

def login_required(f):
    """Decorator to require a user to be logged in."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Authentication required. Please login first.", "warning")
            return redirect(url_for('auth.login'))

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT role FROM users WHERE id = %s", (session['user_id'],))
                user = cursor.fetchone()
        finally:
            conn.close()

        if not user:
            session.clear()
            flash("Your account is no longer available. Please login again.", "warning")
            return redirect(url_for('auth.login'))

        session['role'] = user['role']
        g.authenticated_user_role = user['role']
        return f(*args, **kwargs)
    return decorated_function

def roles_allowed(*roles):
    """Decorator to restrict access to specific roles (citizen, investigator, admin)."""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("Authentication required. Please login first.", "warning")
                return redirect(url_for('auth.login'))
            
            user_role = getattr(g, 'authenticated_user_role', session.get('role'))
            if user_role not in roles:
                # Audit logging handles database failures so authorization remains deterministic.
                log_unauthorized_access(session.get('user_id'), user_role, roles)
                abort(403) # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_unauthorized_access(user_id, current_role, allowed_roles):
    """Logs an unauthorized page access attempt to the audit log."""
    from utils.audit import log_audit
    log_audit(
        user_id=user_id,
        action="UNAUTHORIZED_ACCESS_ATTEMPT",
        description=f"User with role '{current_role}' attempted to access a page requiring roles: {allowed_roles}."
    )
