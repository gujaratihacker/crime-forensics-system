from flask import Blueprint, request, redirect, url_for, flash, session, abort, send_from_directory
from utils.auth import login_required, get_db_connection, roles_allowed
from utils.security import sanitize_string, validate_csrf_token, get_secure_upload_name
from services.moderation_service import moderate_comment
from utils.audit import log_audit
from config import Config
import os

comments_bp = Blueprint('comments', __name__, url_prefix='/comments')

@comments_bp.route('/add/<live_id>', methods=['POST'])
def add_comment(live_id):
    # CSRF check
    token = request.form.get('csrf_token')
    if not validate_csrf_token(token):
        flash("CSRF token verification failed.", "danger")
        return redirect(request.referrer or url_for('live_incidents.public_incidents'))
        
    comment_text = sanitize_string(request.form.get('comment_text'))
    comment_type = sanitize_string(request.form.get('comment_type', 'info'))
    post_anonymously = request.form.get('anonymous') == 'on'
    
    if not comment_text:
        flash("Comment cannot be blank.", "danger")
        return redirect(request.referrer or url_for('live_incidents.public_incidents'))
        
    user_id = session.get('user_id') # Can be None if viewer is not logged in
    
    # Set display username
    if post_anonymously or not user_id:
        username_display = "Anonymous User"
    else:
        username_display = session.get('fullname')
        
    # Moderation check
    mod_res = moderate_comment(comment_text)
    
    proof_stored_filename = None
    proof_original_filename = None
    
    # Handle proof file upload
    if 'proof_file' in request.files:
        file = request.files['proof_file']
        if file and file.filename:
            stored_name = get_secure_upload_name(file.filename)
            filepath = os.path.join(Config.UPLOAD_FOLDER, stored_name)
            file.save(filepath)
            proof_stored_filename = stored_name
            proof_original_filename = file.filename
            
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Check if live incident is active
            cursor.execute("SELECT status FROM live_incidents WHERE id = %s", (live_id,))
            incident = cursor.fetchone()
            if not incident:
                abort(404, "Livestream not found.")
                
            # Insert comment
            cursor.execute("""
                INSERT INTO comments (live_incident_id, user_id, username_display, comment_type, comment_text, is_flagged, moderation_status, proof_stored_filename, proof_original_filename)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                live_id, user_id, username_display, comment_type, comment_text,
                1 if mod_res['is_flagged'] else 0,
                mod_res['moderation_status'],
                proof_stored_filename,
                proof_original_filename
            ))
            comment_id = cursor.lastrowid
            
            # If flagged, write details to flags table
            if mod_res['is_flagged']:
                cursor.execute("""
                    INSERT INTO comment_flags (comment_id, flagged_by, reason)
                    VALUES (%s, %s, %s)
                """, (comment_id, user_id, mod_res['reason']))
                
                flash("Your comment has been submitted and is flagged for review due to security policies.", "warning")
                
                # Write audit log
                log_audit(
                    user_id=user_id,
                    action="COMMENT_FLAGGED",
                    live_incident_id=live_id,
                    description=f"Comment #{comment_id} was automatically flagged for review. Reason: {mod_res['reason']}"
                )
            else:
                flash("Comment posted.", "success")
                
    except Exception as e:
        flash("Failed to post comment.", "danger")
        print(f"COMMENT POST ERROR: {e}")
    finally:
        conn.close()
        
    return redirect(url_for('live_incidents.watch', live_id=live_id))

@comments_bp.route('/moderate/queue')
@login_required
@roles_allowed('admin')
def moderation_queue():
    """Displays flagged comments for admin moderation."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT c.*, f.reason, f.created_at as flagged_at, u.username as flagged_by_user
                FROM comments c
                JOIN comment_flags f ON c.id = f.comment_id
                LEFT JOIN users u ON f.flagged_by = u.id
                WHERE c.moderation_status = 'pending'
                ORDER BY f.created_at DESC
            """)
            flagged_comments = cursor.fetchall()
    finally:
        conn.close()
        
    return render_template('admin/moderation_queue.html', comments=flagged_comments)

@comments_bp.route('/moderate/<action>/<int:comment_id>', methods=['POST'])
@login_required
@roles_allowed('admin')
def moderate_action(action, comment_id):
    # CSRF check
    token = request.form.get('csrf_token')
    if not validate_csrf_token(token):
        flash("CSRF verification failed.", "danger")
        return redirect(url_for('comments.moderation_queue'))
        
    user_id = session.get('user_id')
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Check comment existence
            cursor.execute("SELECT live_incident_id, comment_text FROM comments WHERE id = %s", (comment_id,))
            comment = cursor.fetchone()
            if not comment:
                flash("Comment not found.", "danger")
                return redirect(url_for('comments.moderation_queue'))
                
            if action == 'approve':
                cursor.execute("UPDATE comments SET moderation_status = 'approved', is_flagged = 0 WHERE id = %s", (comment_id,))
                
                log_audit(
                    user_id=user_id,
                    action="COMMENT_APPROVED",
                    live_incident_id=comment['live_incident_id'],
                    description=f"Admin approved comment #{comment_id}: '{comment['comment_text'][:40]}...'"
                )
                flash("Comment approved and displayed publicly.", "success")
                
            elif action == 'hide':
                cursor.execute("UPDATE comments SET moderation_status = 'hidden' WHERE id = %s", (comment_id,))
                
                log_audit(
                    user_id=user_id,
                    action="COMMENT_REJECTED",
                    live_incident_id=comment['live_incident_id'],
                    description=f"Admin rejected/hid comment #{comment_id}: '{comment['comment_text'][:40]}...'"
                )
                flash("Comment rejected and hidden.", "info")
                
    except Exception as e:
        flash("Moderation action failed.", "danger")
        print(f"MODERATE ACTION ERROR: {e}")
    finally:
        conn.close()
        
    return redirect(url_for('comments.moderation_queue'))

@comments_bp.route('/proof/<filename>')
def download_proof(filename):
    """Serves comment proof attachment publicly."""
    return send_from_directory(Config.UPLOAD_FOLDER, filename)
