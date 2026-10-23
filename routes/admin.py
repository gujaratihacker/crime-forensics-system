import re
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort
from werkzeug.security import generate_password_hash
from utils.auth import login_required, get_db_connection, roles_allowed
from utils.security import sanitize_string, validate_csrf_token
from utils.audit import log_audit
from datetime import datetime
from services.case_matching import link_initial_complaint_indicators
from services.awareness_service import ensure_awareness_scams_table

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
SCAM_ICONS = {
    'bi-shield-exclamation', 'bi-envelope-exclamation', 'bi-phone',
    'bi-credit-card', 'bi-person-vcard', 'bi-qr-code', 'bi-chat-square-text'
}


def get_awareness_scam_form():
    scam = {
        'title': sanitize_string(request.form.get('title')),
        'summary': sanitize_string(request.form.get('summary')),
        'warning_signs': sanitize_string(request.form.get('warning_signs')),
        'safety_advice': sanitize_string(request.form.get('safety_advice')),
        'icon': sanitize_string(request.form.get('icon'))
    }
    if not all(scam.values()):
        return None, "All scam content fields are required."
    if len(scam['title']) > 120 or len(scam['summary']) > 2000 or len(scam['warning_signs']) > 1500 or len(scam['safety_advice']) > 1500:
        return None, "One or more scam content fields exceed the allowed length."
    if scam['icon'] not in SCAM_ICONS:
        return None, "Select a valid icon."
    return scam, None

def generate_case_id():
    """Generates a sequential case ID in the format CASE-YYYY-NNNNN."""
    current_year = datetime.now().year
    prefix = f"CASE-{current_year}-"
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id FROM cases 
                WHERE id LIKE %s 
                ORDER BY id DESC LIMIT 1
            """, (f"{prefix}%",))
            last_record = cursor.fetchone()
            
            if last_record:
                last_num = int(last_record['id'].split('-')[2])
                new_num = last_num + 1
            else:
                new_num = 1
                
            return f"{prefix}{new_num:05d}"
    finally:
        conn.close()

@admin_bp.route('/dashboard')
@login_required
@roles_allowed('admin')
def dashboard():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 1. Stats Counter
            cursor.execute("SELECT COUNT(*) as count FROM complaints")
            tot_complaints = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM complaints WHERE status = 'submitted'")
            pending_complaints = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM cases WHERE status != 'closed'")
            active_cases = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM cases WHERE status = 'closed'")
            closed_cases = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM evidence")
            tot_evidence = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM live_incidents WHERE status = 'active'")
            active_streams = cursor.fetchone()['count']
            
            # 2. Get pending/under-review complaints
            cursor.execute("""
                SELECT c.*, u.fullname as citizen_name 
                FROM complaints c
                LEFT JOIN users u ON c.citizen_id = u.id
                WHERE c.status IN ('submitted', 'under_review')
                ORDER BY c.created_at DESC
            """)
            pending_list = cursor.fetchall()
            
            # 3. Get all active cases
            cursor.execute("""
                SELECT ca.id as case_id, ca.status as case_status, ca.created_at,
                       c.id as complaint_id, c.category, c.priority,
                       u.fullname as investigator_name
                FROM cases ca
                JOIN complaints c ON ca.complaint_id = c.id
                LEFT JOIN users u ON ca.investigator_id = u.id
                WHERE ca.status != 'closed'
                ORDER BY ca.created_at DESC
            """)
            active_cases_list = cursor.fetchall()
            
            # 4. Get active investigators
            cursor.execute("""
                SELECT i.*, u.fullname, u.email 
                FROM investigators i
                JOIN users u ON i.user_id = u.id
            """)
            investigators_list = cursor.fetchall()
            
            # 5. Fetch recent audit logs
            cursor.execute("""
                SELECT a.*, u.username 
                FROM audit_logs a
                LEFT JOIN users u ON a.user_id = u.id
                ORDER BY a.timestamp DESC LIMIT 15
            """)
            audit_logs_list = cursor.fetchall()

            # 6. Fetch stats for charts (Category distribution)
            cursor.execute("SELECT category, COUNT(*) as count FROM complaints GROUP BY category")
            category_stats = cursor.fetchall()
            
            # 7. Fetch stats for charts (Priority distribution)
            cursor.execute("SELECT priority, COUNT(*) as count FROM complaints GROUP BY priority")
            priority_stats = cursor.fetchall()

            # 8. Fetch stats for charts (Evidence file type distribution)
            cursor.execute("SELECT file_type, COUNT(*) as count FROM evidence GROUP BY file_type")
            evidence_stats = cursor.fetchall()

            # 9. Fetch stats for charts (Case status distribution)
            cursor.execute("SELECT status, COUNT(*) as count FROM cases GROUP BY status")
            status_stats = cursor.fetchall()
            
    finally:
        conn.close()
        
    return render_template(
        'admin/dashboard.html',
        total_complaints=tot_complaints,
        pending_complaints=pending_complaints,
        active_cases=active_cases,
        closed_cases=closed_cases,
        total_evidence=tot_evidence,
        active_streams=active_streams,
        pending_list=pending_list,
        active_cases_list=active_cases_list,
        investigators=investigators_list,
        audit_logs=audit_logs_list,
        category_stats=category_stats,
        priority_stats=priority_stats,
        evidence_stats=evidence_stats,
        status_stats=status_stats
    )

@admin_bp.route('/investigators/add', methods=['POST'])
@login_required
@roles_allowed('admin')
def add_investigator():
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash("Security token expired or invalid.", "danger")
        return redirect(url_for('admin.dashboard'))

    fullname = sanitize_string(request.form.get('fullname'))
    username = sanitize_string(request.form.get('username'))
    email = sanitize_string(request.form.get('email')).lower()
    phone = sanitize_string(request.form.get('phone'))
    password = request.form.get('password', '')
    rank = sanitize_string(request.form.get('rank')) or 'Junior Detective'
    department = sanitize_string(request.form.get('department')) or 'Cyber Crime Cell'

    if not all([fullname, username, email, phone, password]):
        flash("Name, username, email, phone, and password are required.", "danger")
        return redirect(url_for('admin.dashboard'))

    if len(fullname) > 100 or len(username) > 50 or len(email) > 100 or len(phone) > 20:
        flash("One or more fields exceed the allowed length.", "danger")
        return redirect(url_for('admin.dashboard'))

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        flash("Enter a valid email address.", "danger")
        return redirect(url_for('admin.dashboard'))

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,50}", username):
        flash("Username must be 3-50 characters and use only letters, numbers, dots, underscores, or hyphens.", "danger")
        return redirect(url_for('admin.dashboard'))

    if len(password) < 8 or not any(char.isalpha() for char in password) or not any(char.isdigit() for char in password):
        flash("Password must be at least 8 characters and contain both letters and numbers.", "danger")
        return redirect(url_for('admin.dashboard'))

    if len(rank) > 50 or len(department) > 100:
        flash("Rank or department exceeds the allowed length.", "danger")
        return redirect(url_for('admin.dashboard'))

    conn = get_db_connection()
    try:
        conn.begin()
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
            if cursor.fetchone():
                conn.rollback()
                flash("That username or email is already registered.", "danger")
                return redirect(url_for('admin.dashboard'))

            cursor.execute("""
                INSERT INTO users (username, email, password_hash, phone, fullname, role)
                VALUES (%s, %s, %s, %s, %s, 'investigator')
            """, (username, email, generate_password_hash(password), phone, fullname))
            investigator_id = cursor.lastrowid

            cursor.execute("""
                INSERT INTO investigators (user_id, rank, department)
                VALUES (%s, %s, %s)
            """, (investigator_id, rank, department))
        conn.commit()
    except Exception as e:
        conn.rollback()
        flash("Could not create the investigator account. Please try again.", "danger")
        print(f"INVESTIGATOR CREATION ERROR: {e}")
        return redirect(url_for('admin.dashboard'))
    finally:
        conn.close()

    log_audit(
        user_id=session.get('user_id'),
        action="INVESTIGATOR_CREATED",
        description=f"Admin created investigator account: username={username}, email={email}."
    )
    flash(f"Investigator account for {fullname} was created.", "success")
    return redirect(url_for('admin.dashboard'))


@admin_bp.route('/awareness-scams')
@login_required
@roles_allowed('admin')
def awareness_scams():
    conn = get_db_connection()
    try:
        ensure_awareness_scams_table(conn)
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT s.*, u.fullname AS creator_name
                FROM awareness_scams s
                LEFT JOIN users u ON s.created_by = u.id
                ORDER BY s.updated_at DESC, s.id DESC
            """)
            scams = cursor.fetchall()
    finally:
        conn.close()
    return render_template('admin/awareness_scams.html', scams=scams, scam_icons=sorted(SCAM_ICONS))


@admin_bp.route('/awareness-scams/add', methods=['POST'])
@login_required
@roles_allowed('admin')
def add_awareness_scam():
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash("Security token expired or invalid.", "danger")
        return redirect(url_for('admin.awareness_scams'))

    scam, error = get_awareness_scam_form()
    if error:
        flash(error, "danger")
        return redirect(url_for('admin.awareness_scams'))

    conn = get_db_connection()
    try:
        ensure_awareness_scams_table(conn)
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO awareness_scams (title, summary, warning_signs, safety_advice, icon, created_by)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                scam['title'], scam['summary'], scam['warning_signs'], scam['safety_advice'],
                scam['icon'], session.get('user_id')
            ))
    except Exception as e:
        flash("Could not add the scam entry. Please try again.", "danger")
        print(f"AWARENESS SCAM CREATE ERROR: {e}")
        return redirect(url_for('admin.awareness_scams'))
    finally:
        conn.close()

    log_audit(
        user_id=session.get('user_id'),
        action="AWARENESS_SCAM_CREATED",
        description=f"Admin added awareness scam entry: {scam['title']}."
    )
    flash("Scam entry added to the Awareness Hub.", "success")
    return redirect(url_for('admin.awareness_scams'))


@admin_bp.route('/awareness-scams/<int:scam_id>/edit', methods=['POST'])
@login_required
@roles_allowed('admin')
def edit_awareness_scam(scam_id):
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash("Security token expired or invalid.", "danger")
        return redirect(url_for('admin.awareness_scams'))

    scam, error = get_awareness_scam_form()
    if error:
        flash(error, "danger")
        return redirect(url_for('admin.awareness_scams'))

    conn = get_db_connection()
    try:
        ensure_awareness_scams_table(conn)
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE awareness_scams
                SET title = %s, summary = %s, warning_signs = %s, safety_advice = %s, icon = %s
                WHERE id = %s
            """, (
                scam['title'], scam['summary'], scam['warning_signs'], scam['safety_advice'],
                scam['icon'], scam_id
            ))
            if cursor.rowcount == 0:
                cursor.execute("SELECT id FROM awareness_scams WHERE id = %s", (scam_id,))
                if not cursor.fetchone():
                    flash("Scam entry not found.", "warning")
                    return redirect(url_for('admin.awareness_scams'))
    except Exception as e:
        flash("Could not update the scam entry. Please try again.", "danger")
        print(f"AWARENESS SCAM UPDATE ERROR: {e}")
        return redirect(url_for('admin.awareness_scams'))
    finally:
        conn.close()

    log_audit(
        user_id=session.get('user_id'),
        action="AWARENESS_SCAM_UPDATED",
        description=f"Admin updated awareness scam entry {scam_id}: {scam['title']}."
    )
    flash("Scam entry updated.", "success")
    return redirect(url_for('admin.awareness_scams'))


@admin_bp.route('/awareness-scams/<int:scam_id>/delete', methods=['POST'])
@login_required
@roles_allowed('admin')
def delete_awareness_scam(scam_id):
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash("Security token expired or invalid.", "danger")
        return redirect(url_for('admin.awareness_scams'))

    conn = get_db_connection()
    try:
        ensure_awareness_scams_table(conn)
        with conn.cursor() as cursor:
            cursor.execute("SELECT title FROM awareness_scams WHERE id = %s", (scam_id,))
            scam = cursor.fetchone()
            if not scam:
                flash("Scam entry not found.", "warning")
                return redirect(url_for('admin.awareness_scams'))
            cursor.execute("DELETE FROM awareness_scams WHERE id = %s", (scam_id,))
    except Exception as e:
        flash("Could not remove the scam entry. Please try again.", "danger")
        print(f"AWARENESS SCAM DELETE ERROR: {e}")
        return redirect(url_for('admin.awareness_scams'))
    finally:
        conn.close()

    log_audit(
        user_id=session.get('user_id'),
        action="AWARENESS_SCAM_DELETED",
        description=f"Admin removed awareness scam entry: {scam['title']}."
    )
    flash("Scam entry removed from the Awareness Hub.", "success")
    return redirect(url_for('admin.awareness_scams'))

@admin_bp.route('/complaint/action/<complaint_id>', methods=['POST'])
@login_required
@roles_allowed('admin')
def complaint_action(complaint_id):
    # CSRF Check
    token = request.form.get('csrf_token')
    if not validate_csrf_token(token):
        flash("Security token expired/invalid.", "danger")
        return redirect(url_for('admin.dashboard'))
        
    action = request.form.get('action') # 'approve' or 'reject'
    investigator_id_str = request.form.get('investigator_id')
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Fetch complaint details
            cursor.execute("SELECT * FROM complaints WHERE id = %s", (complaint_id,))
            complaint = cursor.fetchone()
            
            if not complaint:
                flash("Complaint not found.", "danger")
                return redirect(url_for('admin.dashboard'))
                
            if action == 'approve':
                # Create case
                case_id = generate_case_id()
                
                # Determine investigator
                investigator_id = int(investigator_id_str) if investigator_id_str else None
                
                # Update complaint status
                cursor.execute("UPDATE complaints SET status = 'accepted' WHERE id = %s", (complaint_id,))
                
                # Insert case
                cursor.execute("""
                    INSERT INTO cases (id, complaint_id, investigator_id, status)
                    VALUES (%s, %s, %s, 'assigned')
                """, (case_id, complaint_id, investigator_id))
                
                # Auto-parse indicators & link potential serial cases
                link_initial_complaint_indicators(case_id, complaint['contact_indicators'])
                
                # Insert case update timeline
                inv_name = "None"
                if investigator_id:
                    cursor.execute("SELECT fullname FROM users WHERE id = %s", (investigator_id,))
                    inv_res = cursor.fetchone()
                    inv_name = inv_res['fullname'] if inv_res else "None"
                    
                    # Update investigator case count
                    cursor.execute("""
                        UPDATE investigators 
                        SET assigned_cases_count = assigned_cases_count + 1 
                        WHERE user_id = %s
                    """, (investigator_id,))
                
                cursor.execute("""
                    INSERT INTO case_updates (case_id, status, update_message)
                    VALUES (%s, 'assigned', %s)
                """, (case_id, f"Complaint approved. Case {case_id} registered and assigned to investigator: {inv_name}."))
                
                # Log audit
                log_audit(
                    user_id=session.get('user_id'),
                    action="CASE_CREATION",
                    case_id=case_id,
                    description=f"Admin approved complaint {complaint_id}, generated case {case_id}, assigned to {inv_name}."
                )
                
                flash(f"Complaint {complaint_id} approved. Case {case_id} successfully registered.", "success")
                
            elif action == 'reject':
                # Reject complaint
                cursor.execute("UPDATE complaints SET status = 'rejected' WHERE id = %s", (complaint_id,))
                
                log_audit(
                    user_id=session.get('user_id'),
                    action="COMPLAINT_REJECTION",
                    description=f"Admin rejected complaint {complaint_id}."
                )
                flash(f"Complaint {complaint_id} has been marked as rejected.", "info")
                
    except Exception as e:
        flash("Failed to process complaint action.", "danger")
        print(f"COMPLAINT ACTION ERROR: {e}")
    finally:
        conn.close()
        
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/audit-logs')
@login_required
@roles_allowed('admin')
def audit_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Get total count
            cursor.execute("SELECT COUNT(*) as count FROM audit_logs")
            total = cursor.fetchone()['count']
            
            # Fetch page logs
            cursor.execute("""
                SELECT a.*, u.username, u.role
                FROM audit_logs a
                LEFT JOIN users u ON a.user_id = u.id
                ORDER BY a.timestamp DESC
                LIMIT %s OFFSET %s
            """, (per_page, offset))
            logs = cursor.fetchall()
            
    finally:
        conn.close()
        
    total_pages = (total + per_page - 1) // per_page
    return render_template('admin/audit_logs.html', logs=logs, page=page, total_pages=total_pages)
