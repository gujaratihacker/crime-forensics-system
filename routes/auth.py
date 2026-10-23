import os
import re
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from utils.auth import get_db_connection, login_required, roles_allowed
from utils.security import sanitize_string, validate_csrf_token, is_allowed_file, get_secure_upload_name
from utils.audit import log_audit
from config import Config

auth_bp = Blueprint('auth', __name__)

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None

def is_strong_password(password):
    # At least 8 characters, 1 letter, 1 number
    return len(password) >= 8 and any(c.isdigit() for c in password) and any(c.isalpha() for c in password)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect_by_role(session.get('role'))

    form_data = {}
    errors = {}
    form_error = None

    def render_register():
        return render_template(
            'auth/register.html',
            form_data=form_data,
            errors=errors,
            form_error=form_error
        )

    if request.method == 'POST':
        form_data = {
            'fullname': sanitize_string(request.form.get('fullname')),
            'username': sanitize_string(request.form.get('username')),
            'email': sanitize_string(request.form.get('email')),
            'phone': sanitize_string(request.form.get('phone')),
            'doc_type': sanitize_string(request.form.get('doc_type'))
        }
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # CSRF Check
        token = request.form.get('csrf_token')
        if not validate_csrf_token(token):
            form_error = "Security check failed. Please submit the form again."
            return render_register()

        required_fields = {
            'fullname': 'Full name',
            'username': 'Username',
            'email': 'Email address',
            'phone': 'Phone number',
            'doc_type': 'Verification document type'
        }
        for field, label in required_fields.items():
            if not form_data[field]:
                errors[field] = f"{label} is required."

        if not password:
            errors['password'] = "Password is required."
        elif not is_strong_password(password):
            errors['password'] = "Password must be at least 8 characters long and contain both letters and numbers."

        if not confirm_password:
            errors['confirm_password'] = "Please confirm your password."
        elif password != confirm_password:
            errors['confirm_password'] = "Passwords do not match."

        if form_data['email'] and not is_valid_email(form_data['email']):
            errors['email'] = "Please enter a valid email address."

        v_file = request.files.get('verification_file')
        if not v_file or not v_file.filename:
            errors['verification_file'] = "Verification proof document is required."
        elif not is_allowed_file(v_file.filename):
            errors['verification_file'] = "Invalid document format. Allowed types: png, jpg, jpeg, pdf."

        if errors:
            return render_register()

        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor() as cursor:
                # Check for existing username or email
                cursor.execute(
                    "SELECT username, email FROM users WHERE username = %s OR email = %s",
                    (form_data['username'], form_data['email'])
                )
                existing_users = cursor.fetchall()
                if existing_users:
                    if any(user['username'] == form_data['username'] for user in existing_users):
                        errors['username'] = "This username is already registered."
                    if any(user['email'] == form_data['email'] for user in existing_users):
                        errors['email'] = "This email address is already registered."
                    return render_register()

                # Save the verification document only after validation succeeds.
                os.makedirs(Config.VERIFICATION_UPLOAD_FOLDER, exist_ok=True)
                stored_filename = get_secure_upload_name(v_file.filename)
                filepath = os.path.join(Config.VERIFICATION_UPLOAD_FOLDER, stored_filename)
                v_file.save(filepath)
                
                # Insert user
                pw_hash = generate_password_hash(password)
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, phone, fullname, role, verification_doc_type, verification_doc_path)
                    VALUES (%s, %s, %s, %s, %s, 'citizen', %s, %s)
                """, (
                    form_data['username'],
                    form_data['email'],
                    pw_hash,
                    form_data['phone'],
                    form_data['fullname'],
                    form_data['doc_type'],
                    stored_filename
                ))
                
                new_user_id = cursor.lastrowid
                
                # Audit the registration
                log_audit(
                    user_id=new_user_id,
                    action="USER_REGISTRATION",
                    description=f"New citizen account registered: username={form_data['username']}, email={form_data['email']}."
                )
                
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            form_error = "An error occurred during registration. Please try again."
            print(f"REGISTRATION ERROR: {e}")
        finally:
            if conn:
                conn.close()

        return render_register()
            
    return render_register()

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect_by_role(session.get('role'))
        
    if request.method == 'POST':
        # CSRF Check
        token = request.form.get('csrf_token')
        if not validate_csrf_token(token):
            flash("Security check failed (CSRF token missing or invalid).", "danger")
            return render_template('auth/login.html')
            
        username_or_email = sanitize_string(request.form.get('username'))
        password = request.form.get('password')
        
        if not username_or_email or not password:
            flash("Username/Email and Password are required.", "danger")
            return render_template('auth/login.html')
            
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT id, username, password_hash, email, fullname, role 
                    FROM users 
                    WHERE username = %s OR email = %s
                """, (username_or_email, username_or_email))
                user = cursor.fetchone()
                
                if user and check_password_hash(user['password_hash'], password):
                    # Login successful
                    session.clear()
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    session['fullname'] = user['fullname']
                    
                    # Generate a new CSRF token for the session
                    from utils.security import generate_csrf_token
                    generate_csrf_token()
                    
                    log_audit(
                        user_id=user['id'],
                        action="USER_LOGIN_SUCCESS",
                        description=f"Successful login for user '{user['username']}' with role '{user['role']}'."
                    )
                    
                    flash(f"Welcome back, {user['fullname']}!", "success")
                    return redirect_by_role(user['role'])
                else:
                    # Login failed
                    log_audit(
                        user_id=None,
                        action="USER_LOGIN_FAILURE",
                        description=f"Failed login attempt for input username/email: '{username_or_email}'."
                    )
                    flash("Invalid username/email or password.", "danger")
                    
        except Exception as e:
            flash("An error occurred during login. Please try again.", "danger")
            print(f"LOGIN ERROR: {e}")
        finally:
            conn.close()
            
    return render_template('auth/login.html')

@auth_bp.route('/logout')
def logout():
    user_id = session.get('user_id')
    username = session.get('username')
    
    if user_id:
        log_audit(
            user_id=user_id,
            action="USER_LOGOUT",
            description=f"User '{username}' logged out successfully."
        )
        
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('auth.login'))

def redirect_by_role(role):
    if role == 'admin':
        return redirect(url_for('admin.dashboard'))
    elif role == 'investigator':
        return redirect(url_for('investigator.dashboard'))
    else:
        return redirect(url_for('citizen.dashboard'))

@auth_bp.route('/verification/proof/<filename>')
@login_required
@roles_allowed('investigator', 'admin')
def serve_verification(filename):
    # Prevent directory traversal
    filename = os.path.basename(filename)
    return send_from_directory(Config.VERIFICATION_UPLOAD_FOLDER, filename)
