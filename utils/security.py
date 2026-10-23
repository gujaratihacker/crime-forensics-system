import os
import secrets
import html
from flask import session, request, abort
from werkzeug.utils import secure_filename
from config import Config

def generate_csrf_token():
    """Generate and store a CSRF token in session if not present."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token(token_to_verify):
    """Validate that the provided token matches the session CSRF token."""
    session_token = session.get('csrf_token')
    if not session_token or not token_to_verify or not secrets.compare_digest(session_token, token_to_verify):
        return False
    return True

def csrf_protect():
    """CSRF protection helper that can be run before requests."""
    if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
        token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        if not validate_csrf_token(token):
            abort(400, "CSRF token validation failed. Request terminated.")

def sanitize_string(val):
    """Strip whitespace to sanitize input. Jinja's default autoescaping handles XSS safely on render."""
    if val is None:
        return ""
    if not isinstance(val, str):
        return str(val)
    return val.strip()

def is_allowed_file(filename):
    """Check if file extension is permitted."""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in Config.ALLOWED_EXTENSIONS

def get_secure_upload_name(filename):
    """Generate a safe, unique filename using secure_filename and a random prefix."""
    sec_name = secure_filename(filename)
    if not sec_name:
        # Fallback if filename is empty or entirely special characters
        sec_name = "evidence_file"
    
    # Generate random prefix to prevent collisions
    random_prefix = secrets.token_hex(8)
    return f"{random_prefix}_{sec_name}"
