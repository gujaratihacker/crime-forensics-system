from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort
from utils.auth import login_required, get_db_connection, roles_allowed
from utils.security import sanitize_string, validate_csrf_token
from utils.audit import log_audit
from services.ai_analysis import analyze_complaint
from services.case_messages import ensure_case_messages_table
from datetime import datetime

complaints_bp = Blueprint('complaints', __name__, url_prefix='/complaints')

def generate_complaint_id():
    """Generates a sequential complaint ID in the format CR-YYYY-NNNNN."""
    current_year = datetime.now().year
    prefix = f"CR-{current_year}-"
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id FROM complaints 
                WHERE id LIKE %s 
                ORDER BY id DESC LIMIT 1
            """, (f"{prefix}%",))
            last_record = cursor.fetchone()
            
            if last_record:
                # Extract the last 5 digits and increment
                last_num = int(last_record['id'].split('-')[2])
                new_num = last_num + 1
            else:
                new_num = 1
                
            return f"{prefix}{new_num:05d}"
    finally:
        conn.close()

@complaints_bp.route('/submit', methods=['GET', 'POST'])
@login_required
@roles_allowed('citizen')
def submit():
    if request.method == 'POST':
        # CSRF check
        token = request.form.get('csrf_token')
        if not validate_csrf_token(token):
            flash("Security check failed (CSRF token missing or invalid).", "danger")
            return render_template('citizen/report_crime.html')
            
        category = sanitize_string(request.form.get('category'))
        incident_date = sanitize_string(request.form.get('incident_date'))
        incident_time = sanitize_string(request.form.get('incident_time'))
        location = sanitize_string(request.form.get('location'))
        description = sanitize_string(request.form.get('description'))
        victim_info = sanitize_string(request.form.get('victim_info'))
        suspect_info = sanitize_string(request.form.get('suspect_info'))
        
        financial_loss_str = request.form.get('financial_loss', '0')
        try:
            financial_loss = float(financial_loss_str) if financial_loss_str else 0.0
        except ValueError:
            financial_loss = 0.0
            
        additional_info = sanitize_string(request.form.get('additional_info'))
        reporting_mode = sanitize_string(request.form.get('reporting_mode', 'identified'))
        
        # Validations
        if not all([category, incident_date, incident_time, location, description]):
            flash("Please fill in all required fields marked with an asterisk (*).", "danger")
            return render_template('citizen/report_crime.html')
            
        complaint_id = generate_complaint_id()
        user_id = session.get('user_id')
        
        # Call AI Assisted Analysis Service
        ai_res = analyze_complaint(description, category, financial_loss)
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = """
                INSERT INTO complaints (
                    id, citizen_id, category, incident_date, incident_time, location, 
                    description, victim_info, suspect_info, contact_indicators, financial_loss, 
                    additional_info, reporting_mode, status, priority, priority_reason, 
                    ai_category, ai_priority, ai_missing_info, ai_recommended_evidence, ai_summary
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, 
                    %s, %s, %s, %s, %s, 
                    %s, %s, 'submitted', %s, %s, 
                    %s, %s, %s, %s, %s
                )
                """
                cursor.execute(sql, (
                    complaint_id, user_id, category, incident_date, incident_time, location,
                    description, victim_info, suspect_info, ai_res['extracted_indicators'], financial_loss,
                    additional_info, reporting_mode, ai_res['suggested_priority'], ai_res['priority_reason'],
                    ai_res['suggested_category'], ai_res['suggested_priority'], ai_res['missing_info'],
                    ai_res['recommended_evidence'], ai_res['summary']
                ))
                
                # Write an initial case update log for tracking
                cursor.execute("""
                    INSERT INTO audit_logs (user_id, action, case_id, description, ip_address)
                    VALUES (%s, 'COMPLAINT_SUBMISSION', NULL, %s, %s)
                """, (user_id, f"Complaint {complaint_id} submitted via {reporting_mode} mode.", request.remote_addr))
                
            flash(f"Complaint successfully submitted! Reference ID: {complaint_id}", "success")
            return redirect(url_for('citizen.dashboard'))
            
        except Exception as e:
            flash("An error occurred while saving your report. Please try again.", "danger")
            print(f"COMPLAINT SUBMIT ERROR: {e}")
        finally:
            conn.close()
            
    return render_template('citizen/report_crime.html')

@complaints_bp.route('/detail/<complaint_id>')
@login_required
def detail(complaint_id):
    user_id = session.get('user_id')
    user_role = session.get('role')
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Fetch complaint
            cursor.execute("""
                SELECT c.*, sm.platform, sm.crime_type as sm_crime_type, sm.profile_url as sm_profile_url 
                FROM complaints c
                LEFT JOIN social_media_complaints sm ON c.id = sm.complaint_id
                WHERE c.id = %s
            """, (complaint_id,))
            complaint = cursor.fetchone()
            
            if not complaint:
                abort(404, "Complaint not found.")
                
            # Authorization check: Citizens can only see their own complaints
            if user_role == 'citizen' and complaint['citizen_id'] != user_id:
                abort(403, "You are not authorized to view this complaint.")
                
            # Fetch corresponding case if exists
            cursor.execute("""
                SELECT ca.id as case_id, ca.status as case_status, ca.investigator_id, 
                       u.fullname as investigator_name, u.email as investigator_email
                FROM cases ca
                LEFT JOIN users u ON ca.investigator_id = u.id
                WHERE ca.complaint_id = %s
            """, (complaint_id,))
            case_info = cursor.fetchone()

            case_messages = []
            can_view_messages = (
                case_info
                and (
                    (user_role == 'citizen' and complaint['citizen_id'] == user_id)
                    or (user_role == 'investigator' and case_info['investigator_id'] == user_id)
                )
            )
            if can_view_messages:
                ensure_case_messages_table(conn)
                cursor.execute("""
                    SELECT m.message, m.created_at, m.sender_id,
                           u.fullname AS sender_name, u.role AS sender_role
                    FROM case_messages m
                    JOIN users u ON u.id = m.sender_id
                    WHERE m.case_id = %s
                    ORDER BY m.created_at ASC, m.id ASC
                """, (case_info['case_id'],))
                case_messages = cursor.fetchall()
            
            # Fetch evidence uploads
            cursor.execute("""
                SELECT e.*, u.fullname as uploader_name 
                FROM evidence e
                LEFT JOIN users u ON e.uploaded_by = u.id
                WHERE e.complaint_id = %s OR (e.case_id = %s)
                ORDER BY e.upload_timestamp DESC
            """, (complaint_id, case_info['case_id'] if case_info else None))
            evidence_list = cursor.fetchall()
            
            # Fetch tracking log
            timeline = []
            if case_info:
                cursor.execute("""
                    SELECT status, update_message, created_at 
                    FROM case_updates 
                    WHERE case_id = %s 
                    ORDER BY created_at ASC
                """, (case_info['case_id'],))
                timeline = cursor.fetchall()
                
    finally:
        conn.close()
        
    return render_template(
        'citizen/complaint_detail.html',
        complaint=complaint,
        case=case_info,
        evidence=evidence_list,
        timeline=timeline,
        case_messages=case_messages
    )

@complaints_bp.route('/case/<case_id>/messages', methods=['POST'])
@login_required
@roles_allowed('citizen', 'investigator')
def send_case_message(case_id):
    user_id = session.get('user_id')
    user_role = session.get('role')
    redirect_target = (
        url_for('complaints.detail', complaint_id=request.form.get('complaint_id', ''))
        if user_role == 'citizen'
        else url_for('investigator.case_detail', case_id=case_id)
    )

    if not validate_csrf_token(request.form.get('csrf_token')):
        flash("Security check failed. Please try again.", "danger")
        return redirect(redirect_target)

    message = sanitize_string(request.form.get('message'))
    if not message:
        flash("Message cannot be blank.", "danger")
        return redirect(redirect_target)
    if len(message) > 5000:
        flash("Messages must be 5,000 characters or fewer.", "danger")
        return redirect(redirect_target)

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT ca.complaint_id, ca.investigator_id, c.citizen_id
                FROM cases ca
                JOIN complaints c ON c.id = ca.complaint_id
                WHERE ca.id = %s
            """, (case_id,))
            case_info = cursor.fetchone()
            if not case_info:
                abort(404, "Case not found.")

            if user_role == 'citizen':
                if case_info['citizen_id'] != user_id or not case_info['investigator_id']:
                    abort(403, "You can message only the investigator assigned to your case.")
            elif case_info['investigator_id'] != user_id:
                abort(403, "You can message only reporters on cases assigned to you.")

            ensure_case_messages_table(conn)
            cursor.execute("""
                INSERT INTO case_messages (case_id, sender_id, message)
                VALUES (%s, %s, %s)
            """, (case_id, user_id, message))

            log_audit(
                user_id=user_id,
                action="CASE_MESSAGE_SENT",
                case_id=case_id,
                description=f"{user_role.title()} sent a case message."
            )

        flash("Your message was sent.", "success")
        if user_role == 'citizen':
            redirect_target = url_for('complaints.detail', complaint_id=case_info['complaint_id'])
    finally:
        conn.close()

    return redirect(redirect_target)
