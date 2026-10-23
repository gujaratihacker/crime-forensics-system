from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort
from utils.auth import login_required, get_db_connection, roles_allowed
from utils.security import sanitize_string, validate_csrf_token
from utils.audit import log_audit
from services.case_messages import ensure_case_messages_table
from datetime import datetime

investigator_bp = Blueprint('investigator', __name__, url_prefix='/investigator')

@investigator_bp.route('/dashboard')
@login_required
@roles_allowed('investigator')
def dashboard():
    user_id = session.get('user_id')
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 1. Dashboard summary counters
            cursor.execute("""
                SELECT COUNT(*) as count FROM cases 
                WHERE investigator_id = %s AND status != 'closed'
            """, (user_id,))
            assigned_cases = cursor.fetchone()['count']
            
            cursor.execute("""
                SELECT COUNT(*) as count FROM cases 
                WHERE investigator_id = %s AND status = 'closed'
            """, (user_id,))
            closed_cases = cursor.fetchone()['count']
            
            # Count community comments converted to leads on investigator's cases
            cursor.execute("""
                SELECT COUNT(*) as count 
                FROM investigation_leads l
                JOIN cases c ON l.case_id = c.id
                WHERE c.investigator_id = %s
            """, (user_id,))
            total_leads = cursor.fetchone()['count']
            
            # 2. Get list of assigned cases
            cursor.execute("""
                SELECT ca.id as case_id, ca.status as case_status, ca.created_at,
                       c.id as complaint_id, c.category, c.priority, c.reporting_mode,
                       u.fullname as citizen_name
                FROM cases ca
                JOIN complaints c ON ca.complaint_id = c.id
                LEFT JOIN users u ON c.citizen_id = u.id
                WHERE ca.investigator_id = %s
                ORDER BY c.priority = 'CRITICAL' DESC, c.priority = 'HIGH' DESC, ca.created_at DESC
            """, (user_id,))
            cases_list = cursor.fetchall()
            
    finally:
        conn.close()
        
    return render_template(
        'investigator/dashboard.html',
        assigned_cases=assigned_cases,
        closed_cases=closed_cases,
        total_leads=total_leads,
        cases=cases_list
    )

@investigator_bp.route('/case/<case_id>')
@login_required
@roles_allowed('investigator', 'admin')
def case_detail(case_id):
    user_id = session.get('user_id')
    user_role = session.get('role')
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 1. Fetch case details
            cursor.execute("""
                SELECT ca.*, c.category, c.incident_date, c.incident_time, c.location, 
                       c.description, c.victim_info, c.suspect_info, c.contact_indicators,
                       c.financial_loss, c.additional_info, c.reporting_mode, c.citizen_id,
                       u.fullname as citizen_name, u.email as citizen_email, u.phone as citizen_phone,
                       u.verification_doc_type as citizen_doc_type, u.verification_doc_path as citizen_doc_path,
                       i.fullname as investigator_name,
                       sm.platform, sm.crime_type as sm_crime_type, sm.profile_url as sm_profile_url
                FROM cases ca
                JOIN complaints c ON ca.complaint_id = c.id
                LEFT JOIN users u ON c.citizen_id = u.id
                LEFT JOIN users i ON ca.investigator_id = i.id
                LEFT JOIN social_media_complaints sm ON c.id = sm.complaint_id
                WHERE ca.id = %s
            """, (case_id,))
            case_info = cursor.fetchone()
            
            if not case_info:
                abort(404, "Case not found.")
                
            # Authorization check: investigators can only view their own assigned cases (admins can see all)
            if user_role == 'investigator' and case_info['investigator_id'] != user_id:
                abort(403, "You are not authorized to access this case file.")

            ensure_case_messages_table(conn)
            cursor.execute("""
                SELECT m.message, m.created_at, m.sender_id,
                       u.fullname AS sender_name, u.role AS sender_role
                FROM case_messages m
                JOIN users u ON u.id = m.sender_id
                WHERE m.case_id = %s
                ORDER BY m.created_at ASC, m.id ASC
            """, (case_id,))
            case_messages = cursor.fetchall()
                
            # 2. Fetch evidence linked to this case (includes complaint evidence)
            cursor.execute("""
                SELECT e.*, u.fullname as uploader_name 
                FROM evidence e
                LEFT JOIN users u ON e.uploaded_by = u.id
                WHERE e.case_id = %s OR e.complaint_id = %s
                ORDER BY e.upload_timestamp DESC
            """, (case_id, case_info['complaint_id']))
            evidence_list = cursor.fetchall()
            
            # 3. Fetch case notes
            cursor.execute("""
                SELECT n.*, u.fullname as investigator_name 
                FROM investigation_notes n
                JOIN users u ON n.investigator_id = u.id
                WHERE n.case_id = %s
                ORDER BY n.created_at DESC
            """, (case_id,))
            notes_list = cursor.fetchall()
            
            # 4. Fetch case updates timeline
            cursor.execute("""
                SELECT status, update_message, created_at 
                FROM case_updates 
                WHERE case_id = %s 
                ORDER BY created_at DESC
            """, (case_id,))
            timeline = cursor.fetchall()
            
            # 5. Fetch Suspects and their identifiers
            cursor.execute("SELECT * FROM suspects WHERE case_id = %s", (case_id,))
            suspects = cursor.fetchall()
            
            suspect_ids_list = []
            for s in suspects:
                cursor.execute("SELECT * FROM suspect_identifiers WHERE suspect_id = %s", (s['id'],))
                s_indicators = cursor.fetchall()
                suspect_ids_list.append({
                    'suspect': s,
                    'identifiers': s_indicators
                })
                
            # 6. Fetch community comments converted to leads
            cursor.execute("""
                SELECT l.*, c.comment_text, c.username_display, c.comment_type, u.fullname as creator_name
                FROM investigation_leads l
                JOIN comments c ON l.source_comment_id = c.id
                LEFT JOIN users u ON l.created_by = u.id
                WHERE l.case_id = %s
                ORDER BY l.created_at DESC
            """, (case_id,))
            leads = cursor.fetchall()
            
            # 7. Check for related cases
            # We fetch related cases from database matching our list of identifiers
            cursor.execute("""
                SELECT r.*, c2.id as match_case_id, c2.status as match_status, comp.category as match_category
                FROM related_cases r
                JOIN cases c2 ON (r.case_id_1 = c2.id OR r.case_id_2 = c2.id)
                JOIN complaints comp ON c2.complaint_id = comp.id
                WHERE (r.case_id_1 = %s OR r.case_id_2 = %s) AND c2.id != %s
            """, (case_id, case_id, case_id))
            related_cases_list = cursor.fetchall()
            
            # 8. Fetch all comments from any live incidents linked to this case
            cursor.execute("""
                SELECT c.*, li.id as live_id
                FROM comments c
                JOIN live_incidents li ON c.live_incident_id = li.id
                JOIN evidence e ON li.id = e.live_incident_id
                WHERE e.case_id = %s AND c.moderation_status = 'approved'
                ORDER BY c.created_at DESC
            """, (case_id,))
            stream_comments = cursor.fetchall()
            
    finally:
        conn.close()
        
    return render_template(
        'investigator/case_detail.html',
        case=case_info,
        evidence=evidence_list,
        notes=notes_list,
        case_messages=case_messages,
        timeline=timeline,
        suspects=suspect_ids_list,
        leads=leads,
        related_cases=related_cases_list,
        stream_comments=stream_comments
    )

@investigator_bp.route('/case/update-status/<case_id>', methods=['POST'])
@login_required
@roles_allowed('investigator', 'admin')
def update_status(case_id):
    # CSRF Check
    token = request.form.get('csrf_token')
    if not validate_csrf_token(token):
        flash("CSRF token invalid.", "danger")
        return redirect(url_for('investigator.case_detail', case_id=case_id))
        
    new_status = sanitize_string(request.form.get('status'))
    message = sanitize_string(request.form.get('message'))
    
    if not new_status or not message:
        flash("Status and update message are required.", "danger")
        return redirect(url_for('investigator.case_detail', case_id=case_id))
        
    user_id = session.get('user_id')
    user_role = session.get('role')
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Check ownership
            cursor.execute("SELECT investigator_id, status FROM cases WHERE id = %s", (case_id,))
            case = cursor.fetchone()
            
            if not case:
                abort(404, "Case file not found.")
                
            if user_role == 'investigator' and case['investigator_id'] != user_id:
                abort(403)
                
            # Update status
            closed_at = datetime.now() if new_status == 'closed' else None
            
            if closed_at:
                cursor.execute("""
                    UPDATE cases 
                    SET status = %s, closed_at = %s 
                    WHERE id = %s
                """, (new_status, closed_at, case_id))
            else:
                cursor.execute("""
                    UPDATE cases 
                    SET status = %s 
                    WHERE id = %s
                """, (new_status, case_id))
                
            # Add updates timeline
            cursor.execute("""
                INSERT INTO case_updates (case_id, status, update_message)
                VALUES (%s, %s, %s)
            """, (case_id, new_status, message))
            
            log_audit(
                user_id=user_id,
                action="CASE_STATUS_CHANGE",
                case_id=case_id,
                description=f"Investigator changed case status from '{case['status']}' to '{new_status}' with message: {message}."
            )
            
            flash(f"Case status successfully updated to {new_status.replace('_', ' ').title()}.", "success")
            
    except Exception as e:
        flash("Failed to update status.", "danger")
        print(f"CASE STATUS UPDATE ERROR: {e}")
    finally:
        conn.close()
        
    return redirect(url_for('investigator.case_detail', case_id=case_id))

@investigator_bp.route('/case/add-note/<case_id>', methods=['POST'])
@login_required
@roles_allowed('investigator')
def add_note(case_id):
    # CSRF Check
    token = request.form.get('csrf_token')
    if not validate_csrf_token(token):
        flash("CSRF token invalid.", "danger")
        return redirect(url_for('investigator.case_detail', case_id=case_id))
        
    note_text = sanitize_string(request.form.get('note_text'))
    
    if not note_text:
        flash("Note content cannot be blank.", "danger")
        return redirect(url_for('investigator.case_detail', case_id=case_id))
        
    user_id = session.get('user_id')
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Check authorization
            cursor.execute("SELECT investigator_id FROM cases WHERE id = %s", (case_id,))
            case = cursor.fetchone()
            
            if not case or case['investigator_id'] != user_id:
                abort(403)
                
            # Insert note
            cursor.execute("""
                INSERT INTO investigation_notes (case_id, investigator_id, note_text)
                VALUES (%s, %s, %s)
            """, (case_id, user_id, note_text))
            
            log_audit(
                user_id=user_id,
                action="INVESTIGATION_NOTE_ADD",
                case_id=case_id,
                description=f"Investigator added an investigation note: '{note_text[:60]}...'"
            )
            
            flash("Investigation note successfully saved.", "success")
            
    except Exception as e:
        flash("Failed to add note.", "danger")
        print(f"ADD NOTE ERROR: {e}")
    finally:
        conn.close()
        
    return redirect(url_for('investigator.case_detail', case_id=case_id))

@investigator_bp.route('/case/add-suspect/<case_id>', methods=['POST'])
@login_required
@roles_allowed('investigator')
def add_suspect(case_id):
    # CSRF Check
    token = request.form.get('csrf_token')
    if not validate_csrf_token(token):
        flash("CSRF token invalid.", "danger")
        return redirect(url_for('investigator.case_detail', case_id=case_id))
        
    suspect_name = sanitize_string(request.form.get('name'))
    description = sanitize_string(request.form.get('description'))
    
    identifier_type = sanitize_string(request.form.get('identifier_type'))
    identifier_val = sanitize_string(request.form.get('identifier_value'))
    
    if not suspect_name:
        flash("Suspect name is required.", "danger")
        return redirect(url_for('investigator.case_detail', case_id=case_id))
        
    user_id = session.get('user_id')
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Check ownership
            cursor.execute("SELECT investigator_id FROM cases WHERE id = %s", (case_id,))
            case = cursor.fetchone()
            
            if not case or case['investigator_id'] != user_id:
                abort(403)
                
            # Create suspect record
            cursor.execute("""
                INSERT INTO suspects (case_id, name, description)
                VALUES (%s, %s, %s)
            """, (case_id, suspect_name, description))
            suspect_id = cursor.lastrowid
            
            # If an identifier is provided, save it
            if identifier_type and identifier_val:
                cursor.execute("""
                    INSERT INTO suspect_identifiers (suspect_id, identifier_type, identifier_value)
                    VALUES (%s, %s, %s)
                """, (suspect_id, identifier_type, identifier_val))
                
                # Proactively call related case detector logic
                from services.case_matching import find_and_link_related_cases
                find_and_link_related_cases(case_id, identifier_type, identifier_val)
                
            log_audit(
                user_id=user_id,
                action="SUSPECT_INTEL_ADD",
                case_id=case_id,
                description=f"Investigator recorded suspect '{suspect_name}' with key identifier '{identifier_type}:{identifier_val}'."
            )
            
            flash(f"Suspect '{suspect_name}' intelligence recorded.", "success")
            
    except Exception as e:
        flash("Failed to add suspect details.", "danger")
        print(f"ADD SUSPECT ERROR: {e}")
    finally:
        conn.close()
        
    return redirect(url_for('investigator.case_detail', case_id=case_id))

@investigator_bp.route('/case/convert-lead/<case_id>/<int:comment_id>', methods=['POST'])
@login_required
@roles_allowed('investigator')
def convert_lead(case_id, comment_id):
    # CSRF Check
    token = request.form.get('csrf_token')
    if not validate_csrf_token(token):
        flash("CSRF verification failed.", "danger")
        return redirect(url_for('investigator.case_detail', case_id=case_id))
        
    user_id = session.get('user_id')
    current_year = datetime.now().year
    prefix = f"LEAD-{current_year}-"
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Generate Lead ID
            cursor.execute("SELECT id FROM investigation_leads WHERE id LIKE %s ORDER BY id DESC LIMIT 1", (f"{prefix}%",))
            last_record = cursor.fetchone()
            
            if last_record:
                last_num = int(last_record['id'].split('-')[2])
                new_num = last_num + 1
            else:
                new_num = 1
            lead_id = f"{prefix}{new_num:05d}"
            
            # Check duplicates
            cursor.execute("SELECT id FROM investigation_leads WHERE source_comment_id = %s AND case_id = %s", (comment_id, case_id))
            exists = cursor.fetchone()
            if exists:
                flash("Comment already converted to an active investigation lead.", "warning")
                return redirect(url_for('investigator.case_detail', case_id=case_id))
                
            # Insert lead
            cursor.execute("""
                INSERT INTO investigation_leads (id, case_id, source_comment_id, created_by, status)
                VALUES (%s, %s, %s, %s, 'new')
            """, (lead_id, case_id, comment_id, user_id))
            
            log_audit(
                user_id=user_id,
                action="LEAD_CONVERSION",
                case_id=case_id,
                description=f"Investigator converted comment #{comment_id} into lead {lead_id}."
            )
            flash(f"Comment successfully converted to Lead: {lead_id}.", "success")
            
    except Exception as e:
        flash("Failed to convert comment to lead.", "danger")
        print(f"CONVERT LEAD ERROR: {e}")
    finally:
        conn.close()
        
    return redirect(url_for('investigator.case_detail', case_id=case_id))
