import os
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort, send_from_directory
from utils.auth import login_required, get_db_connection
from utils.security import validate_csrf_token, sanitize_string, get_secure_upload_name
from config import Config
from datetime import datetime

missing_persons_bp = Blueprint('missing_persons', __name__, url_prefix='/missing-persons')

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def is_allowed_image(filename):
    """Verify that only standard image formats are accepted."""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_IMAGE_EXTENSIONS

def generate_missing_person_id():
    """Generates a sequential missing person ID in the format MP-YYYY-NNNNN."""
    current_year = datetime.now().year
    prefix = f"MP-{current_year}-"
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id FROM missing_persons 
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

@missing_persons_bp.route('/')
def list_missing():
    """Renders the dashboard listing all reported missing persons."""
    search_query = request.args.get('search', '').strip()
    status_filter = request.args.get('status', 'missing').strip()
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Clean up records marked found more than 2 days ago
            cursor.execute("DELETE FROM missing_persons WHERE status = 'found' AND found_at <= NOW() - INTERVAL 2 DAY")
            
            if search_query:
                cursor.execute("""
                    SELECT * FROM missing_persons 
                    WHERE status = %s AND (fullname LIKE %s OR last_seen_location LIKE %s)
                    ORDER BY created_at DESC
                """, (status_filter, f"%{search_query}%", f"%{search_query}%"))
            else:
                cursor.execute("""
                    SELECT * FROM missing_persons 
                    WHERE status = %s 
                    ORDER BY created_at DESC
                """, (status_filter,))
                
            missing_list = cursor.fetchall()
    finally:
        conn.close()
        
    return render_template('missing_persons/list.html', missing_list=missing_list, search_query=search_query, status_filter=status_filter)

@missing_persons_bp.route('/report', methods=['GET', 'POST'])
@login_required
def report_missing():
    """Allows authenticated citizens to report a new missing person."""
    if request.method == 'POST':
        # CSRF check
        token = request.form.get('csrf_token')
        if not validate_csrf_token(token):
            flash("Security check failed (CSRF token missing or invalid).", "danger")
            return render_template('missing_persons/report.html')
            
        fullname = sanitize_string(request.form.get('fullname'))
        age_str = request.form.get('age')
        gender = sanitize_string(request.form.get('gender'))
        contact_phone = sanitize_string(request.form.get('contact_phone'))
        last_seen_date = request.form.get('last_seen_date')
        last_seen_location = sanitize_string(request.form.get('last_seen_location'))
        description = sanitize_string(request.form.get('description'))
        
        try:
            age = int(age_str)
        except (ValueError, TypeError):
            flash("Please enter a valid age.", "danger")
            return render_template('missing_persons/report.html')
            
        photo_file = request.files.get('photo')
        photo_filename = None
        
        # Handle file upload safely
        if photo_file and photo_file.filename:
            if not is_allowed_image(photo_file.filename):
                flash("Invalid file format. Only standard images (PNG, JPG, JPEG, GIF) are allowed.", "danger")
                return render_template('missing_persons/report.html')
                
            sec_name = get_secure_upload_name(photo_file.filename)
            upload_path = os.path.join(Config.MISSING_PERSONS_UPLOAD_FOLDER, sec_name)
            
            # Ensure folder exists
            if not os.path.exists(Config.MISSING_PERSONS_UPLOAD_FOLDER):
                os.makedirs(Config.MISSING_PERSONS_UPLOAD_FOLDER)
                
            photo_file.save(upload_path)
            photo_filename = sec_name

        missing_id = generate_missing_person_id()
        citizen_id = session.get('user_id')
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO missing_persons 
                    (id, citizen_id, fullname, age, gender, contact_phone, last_seen_date, last_seen_location, description, photo_path)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (missing_id, citizen_id, fullname, age, gender, contact_phone, last_seen_date, last_seen_location, description, photo_filename))
                
                # Log audit
                from utils.audit import log_audit
                log_audit(
                    user_id=citizen_id,
                    action="REPORT_MISSING_PERSON",
                    description=f"Citizen logged missing person report: {fullname} (ID: {missing_id})."
                )
                
            flash(f"Missing person report logged successfully! ID: {missing_id}", "success")
            return redirect(url_for('missing_persons.list_missing'))
        except Exception as e:
            flash(f"Failed to submit report. Please check details. Error: {str(e)}", "danger")
        finally:
            conn.close()

    return render_template('missing_persons/report.html')

@missing_persons_bp.route('/<id>')
def detail_missing(id):
    """Renders details of a missing person, sighting details, and comments."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM missing_persons WHERE id = %s", (id,))
            person = cursor.fetchone()
            if not person:
                abort(404)
                
            cursor.execute("""
                SELECT * FROM missing_person_comments 
                WHERE missing_person_id = %s 
                ORDER BY created_at DESC
            """, (id,))
            comments = cursor.fetchall()
    finally:
        conn.close()
        
    return render_template('missing_persons/detail.html', person=person, comments=comments)

@missing_persons_bp.route('/<id>/comment', methods=['POST'])
def comment_missing(id):
    """Handles submission of community updates or sightings for a missing person."""
    token = request.form.get('csrf_token')
    if not validate_csrf_token(token):
        flash("Security check failed (CSRF token missing or invalid).", "danger")
        return redirect(url_for('missing_persons.detail_missing', id=id))
        
    comment_text = sanitize_string(request.form.get('comment_text'))
    last_seen_location = sanitize_string(request.form.get('last_seen_location'))
    last_seen_date = request.form.get('last_seen_date')
    identification_details = sanitize_string(request.form.get('identification_details'))
    
    if not last_seen_date:
        last_seen_date = None
        
    if not comment_text:
        flash("Comment/sighting text is required.", "danger")
        return redirect(url_for('missing_persons.detail_missing', id=id))
        
    user_id = session.get('user_id')
    username_display = session.get('fullname') if user_id else "Anonymous Citizen"
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO missing_person_comments 
                (missing_person_id, user_id, username_display, last_seen_location, last_seen_date, identification_details, comment_text)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (id, user_id, username_display, last_seen_location, last_seen_date, identification_details, comment_text))
            
            # Log audit
            if user_id:
                from utils.audit import log_audit
                log_audit(
                    user_id=user_id,
                    action="MISSING_PERSON_SIGHTING_COMMENT",
                    description=f"Submitted sighting comment on missing person {id}."
                )
                
        flash("Sighting comment submitted successfully.", "success")
    finally:
        conn.close()
        
    return redirect(url_for('missing_persons.detail_missing', id=id))

@missing_persons_bp.route('/photo/<filename>')
def serve_photo(filename):
    """Serves the uploaded missing person photograph."""
    return send_from_directory(Config.MISSING_PERSONS_UPLOAD_FOLDER, filename)

@missing_persons_bp.route('/<id>/update-status', methods=['POST'])
@login_required
def update_status(id):
    """Allows investigators and the reporting citizen to change the status of a missing person."""
    token = request.form.get('csrf_token')
    if not validate_csrf_token(token):
        flash("Security check failed (CSRF token missing or invalid).", "danger")
        return redirect(url_for('missing_persons.detail_missing', id=id))
        
    new_status = sanitize_string(request.form.get('status'))
    if new_status not in ['missing', 'found']:
        flash("Invalid status selected.", "danger")
        return redirect(url_for('missing_persons.detail_missing', id=id))
        
    user_id = session.get('user_id')
    user_role = session.get('role')
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT citizen_id, fullname FROM missing_persons WHERE id = %s", (id,))
            person = cursor.fetchone()
            if not person:
                abort(404)
                
            # Authorization: only reporter citizen OR investigator/admin
            if person['citizen_id'] != user_id and user_role not in ['investigator', 'admin']:
                abort(403, "You do not have permission to update the status of this report.")
                
            if new_status == 'found':
                cursor.execute("""
                    UPDATE missing_persons 
                    SET status = 'found', found_at = NOW() 
                    WHERE id = %s
                """, (id,))
                
                # Log audit
                from utils.audit import log_audit
                log_audit(
                    user_id=user_id,
                    action="MISSING_PERSON_FOUND",
                    description=f"Marked missing person {person['fullname']} (ID: {id}) as FOUND."
                )
                flash("Status updated to FOUND. This record will automatically be deleted from the system in 2 days.", "success")
            else:
                cursor.execute("""
                    UPDATE missing_persons 
                    SET status = 'missing', found_at = NULL 
                    WHERE id = %s
                """, (id,))
                flash("Status reverted to MISSING.", "info")
                
    except Exception as e:
        flash(f"Failed to update status: {e}", "danger")
    finally:
        conn.close()
        
    return redirect(url_for('missing_persons.detail_missing', id=id))
