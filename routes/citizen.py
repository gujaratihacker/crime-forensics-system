from flask import Blueprint, render_template, session, redirect, url_for, request, flash
from utils.auth import login_required, roles_allowed, get_db_connection
from utils.security import sanitize_string, validate_csrf_token
from utils.audit import log_audit

citizen_bp = Blueprint('citizen', __name__, url_prefix='/citizen')

@citizen_bp.route('/dashboard')
@login_required
@roles_allowed('citizen')
def dashboard():
    user_id = session.get('user_id')
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 1. Total complaints
            cursor.execute("SELECT COUNT(*) as count FROM complaints WHERE citizen_id = %s", (user_id,))
            total_complaints = cursor.fetchone()['count']
            
            # 2. Active complaints (not closed, and corresponding cases not closed)
            cursor.execute("""
                SELECT COUNT(*) as count 
                FROM complaints c
                LEFT JOIN cases ca ON c.id = ca.complaint_id
                WHERE c.citizen_id = %s 
                  AND (c.status IN ('submitted', 'under_review') 
                       OR (c.status = 'accepted' AND (ca.status IS NULL OR ca.status != 'closed')))
            """, (user_id,))
            active_complaints = cursor.fetchone()['count']
            
            # 3. Closed complaints (rejected, or resolved/closed cases)
            cursor.execute("""
                SELECT COUNT(*) as count 
                FROM complaints c
                LEFT JOIN cases ca ON c.id = ca.complaint_id
                WHERE c.citizen_id = %s 
                  AND (c.status = 'rejected' OR ca.status = 'closed')
            """, (user_id,))
            closed_complaints = cursor.fetchone()['count']
            
            # 4. Total evidence uploaded
            cursor.execute("SELECT COUNT(*) as count FROM evidence WHERE uploaded_by = %s", (user_id,))
            total_evidence = cursor.fetchone()['count']
            
            # 5. List of complaints
            cursor.execute("""
                SELECT c.id, c.category, c.incident_date, c.status, c.priority, c.reporting_mode, c.created_at,
                       ca.id as case_id, ca.status as case_status
                FROM complaints c
                LEFT JOIN cases ca ON c.id = ca.complaint_id
                WHERE c.citizen_id = %s
                ORDER BY c.created_at DESC
            """, (user_id,))
            complaints_list = cursor.fetchall()
            
    finally:
        conn.close()
        
    return render_template(
        'citizen/dashboard.html',
        total_complaints=total_complaints,
        active_complaints=active_complaints,
        closed_complaints=closed_complaints,
        total_evidence=total_evidence,
        complaints=complaints_list
    )

@citizen_bp.route('/profile/edit', methods=['GET', 'POST'])
@login_required
@roles_allowed('citizen')
def edit_profile():
    user_id = session.get('user_id')
    
    if request.method == 'POST':
        token = request.form.get('csrf_token')
        if not validate_csrf_token(token):
            flash("Security check failed (CSRF token missing or invalid).", "danger")
            return redirect(url_for('citizen.edit_profile'))
            
        fullname = sanitize_string(request.form.get('fullname'))
        email = sanitize_string(request.form.get('email'))
        phone = sanitize_string(request.form.get('phone'))
        
        if not fullname or not email or not phone:
            flash("All fields are required.", "danger")
            return redirect(url_for('citizen.edit_profile'))
            
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                # Check email uniqueness
                cursor.execute("SELECT id FROM users WHERE email = %s AND id != %s", (email, user_id))
                existing_email = cursor.fetchone()
                if existing_email:
                    flash("Email address is already in use by another user.", "danger")
                    return redirect(url_for('citizen.edit_profile'))
                    
                # Update details
                cursor.execute("""
                    UPDATE users 
                    SET fullname = %s, email = %s, phone = %s 
                    WHERE id = %s
                """, (fullname, email, phone, user_id))
                
                session['fullname'] = fullname
                
                log_audit(
                    user_id=user_id,
                    action="PROFILE_UPDATE",
                    description=f"Updated personal profile (Name: {fullname}, Email: {email}, Phone: {phone})."
                )
                
            flash("Profile updated successfully.", "success")
            return redirect(url_for('citizen.dashboard'))
        except Exception as e:
            flash("Failed to update profile.", "danger")
            print(f"PROFILE UPDATE ERROR: {e}")
        finally:
            conn.close()
            
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT fullname, email, phone FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
    finally:
        conn.close()
        
    return render_template('citizen/edit_profile.html', user=user)
