from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort, send_from_directory, jsonify, current_app
from utils.auth import login_required, get_db_connection, roles_allowed
from utils.security import sanitize_string, validate_csrf_token
from services.evidence_service import generate_evidence_id
from services.hash_service import calculate_sha256
from services.moderation_service import moderate_comment
from utils.audit import log_audit
from config import Config
from datetime import datetime
import base64
import os
import secrets

live_bp = Blueprint('live_incidents', __name__, url_prefix='/live')

def generate_live_id():
    """Generates a sequential live incident ID in the format LIVE-YYYY-NNNNN."""
    current_year = datetime.now().year
    prefix = f"LIVE-{current_year}-"
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id FROM live_incidents 
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

@live_bp.route('/start', methods=['GET'])
@login_required
@roles_allowed('citizen')
def start_live_incident_get():
    # Renders the initial start selection page (identified or anonymous)
    return render_template('live/start_selection.html')

@live_bp.route('/start', methods=['POST'])
@login_required
@roles_allowed('citizen')
def start_live_incident_post():
    # CSRF Check
    token = request.form.get('csrf_token')
    if not validate_csrf_token(token):
        flash("CSRF token verification failed.", "danger")
        return redirect(url_for('live_incidents.start_live_incident_get'))
        
    category = sanitize_string(request.form.get('category'))
    location_approx = sanitize_string(request.form.get('location_approx'))
    reporting_mode = sanitize_string(request.form.get('reporting_mode', 'identified'))
    description = sanitize_string(request.form.get('description'))
    
    if not category or not location_approx:
        flash("Category and approximate area/location are required.", "danger")
        return redirect(url_for('live_incidents.start_live_incident_get'))
        
    live_id = generate_live_id()
    user_id = session.get('user_id')
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO live_incidents (id, reporter_id, category, location_approx, status, reporting_mode, description)
                VALUES (%s, %s, %s, %s, 'active', %s, %s)
            """, (live_id, user_id, category, location_approx, reporting_mode, description))
            
            # Log audit
            log_audit(
                user_id=user_id,
                action="LIVESTREAM_START",
                live_incident_id=live_id,
                description=f"Citizen started live incident report {live_id} ({category}) in {reporting_mode} mode."
            )
            
        return redirect(url_for('live_incidents.stream_console', live_id=live_id))
    except Exception as e:
        flash("Failed to start live stream session.", "danger")
        print(f"START STREAM ERROR: {e}")
        return redirect(url_for('live_incidents.start_live_incident_get'))
    finally:
        conn.close()

@live_bp.route('/stream-console/<live_id>')
@login_required
@roles_allowed('citizen')
def stream_console(live_id):
    user_id = session.get('user_id')
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM live_incidents WHERE id = %s", (live_id,))
            incident = cursor.fetchone()
            
            if not incident or incident['reporter_id'] != user_id or incident['status'] != 'active':
                flash("Unauthorized access or inactive stream.", "danger")
                return redirect(url_for('citizen.dashboard'))
    finally:
        conn.close()
        
    return render_template('live/stream_console.html', incident=incident)

@live_bp.route('/post-frame/<live_id>', methods=['POST'])
@login_required
@roles_allowed('citizen')
def post_frame(live_id):
    # Receives base64 image data and writes it to file
    user_id = session.get('user_id')
    data = request.get_json()
    if not data or 'frame' not in data:
        return jsonify({'error': 'No image data provided'}), 400
        
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT reporter_id, status FROM live_incidents WHERE id = %s", (live_id,))
            incident = cursor.fetchone()
            
            if not incident or incident['reporter_id'] != user_id or incident['status'] != 'active':
                return jsonify({'error': 'Unauthorized or inactive stream'}), 403
    finally:
        conn.close()
        
    # Save the base64 snapshot
    try:
        header, encoded = data['frame'].split(",", 1)
        image_data = base64.b64decode(encoded)
        
        filename = f"{live_id}.jpg"
        filepath = os.path.join(Config.LIVE_SNAPSHOTS_FOLDER, filename)
        
        with open(filepath, "wb") as f:
            f.write(image_data)
            
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'error': f"Failed to save frame: {e}"}), 500

@live_bp.route('/snapshot/<live_id>')
def get_snapshot(live_id):
    """Serves the latest JPEG snapshot for the live stream."""
    filename = f"{live_id}.jpg"
    filepath = os.path.join(Config.LIVE_SNAPSHOTS_FOLDER, filename)
    
    try:
        if os.path.exists(filepath):
            return send_from_directory(Config.LIVE_SNAPSHOTS_FOLDER, filename)
    except (PermissionError, FileNotFoundError):
        # Gracefully handle file sharing violations on Windows or missing files during fast updates
        pass
    except Exception:
        pass
        
    # Return fallback placeholder frame
    fallback_dir = os.path.join(current_app.root_path, 'static', 'images')
    return send_from_directory(fallback_dir, 'live_fallback.jpg')

@live_bp.route('/public')
def public_incidents():
    """Lists active/public livestream feeds."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT l.*, u.fullname as reporter_name 
                FROM live_incidents l
                LEFT JOIN users u ON l.reporter_id = u.id
                WHERE l.status = 'active'
                ORDER BY l.started_at DESC
            """)
            active_list = cursor.fetchall()
            
            cursor.execute("""
                SELECT l.*, u.fullname as reporter_name 
                FROM live_incidents l
                LEFT JOIN users u ON l.reporter_id = u.id
                WHERE l.status = 'completed' AND l.saved_video_evidence_id IS NOT NULL
                ORDER BY l.ended_at DESC LIMIT 10
            """)
            completed_list = cursor.fetchall()
    finally:
        conn.close()
        
    return render_template('live/public_incidents.html', active=active_list, completed=completed_list)

@live_bp.route('/watch/<live_id>')
def watch(live_id):
    """Room details page for watching live streams."""
    conn = get_db_connection()
    video_filename = None
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT l.*, u.fullname as reporter_name 
                FROM live_incidents l
                LEFT JOIN users u ON l.reporter_id = u.id
                WHERE l.id = %s
            """, (live_id,))
            incident = cursor.fetchone()
            
            if not incident:
                abort(404, "Livestream incident not found.")
                
            # Fetch corresponding video filename from evidence table
            if incident['saved_video_evidence_id']:
                cursor.execute("SELECT stored_filename FROM evidence WHERE id = %s", (incident['saved_video_evidence_id'],))
                evidence_row = cursor.fetchone()
                if evidence_row:
                    video_filename = evidence_row['stored_filename']

            # Fetch comments
            cursor.execute("""
                SELECT * FROM comments 
                WHERE live_incident_id = %s AND moderation_status = 'approved'
                ORDER BY created_at ASC
            """, (live_id,))
            comments = cursor.fetchall()
            
            # Simulated viewer sessions count
            viewer_session_id = session.get('user_id') or request.remote_addr
            
            # Check if session exists in live_viewers
            cursor.execute("""
                SELECT id FROM live_viewers 
                WHERE live_incident_id = %s AND session_id = %s
            """, (live_id, viewer_session_id))
            viewer_exists = cursor.fetchone()
            
            if not viewer_exists and incident['status'] == 'active':
                cursor.execute("""
                    INSERT INTO live_viewers (live_incident_id, session_id) 
                    VALUES (%s, %s)
                """, (live_id, viewer_session_id))
                
                # Increment count
                cursor.execute("""
                    UPDATE live_incidents 
                    SET viewer_count = viewer_count + 1 
                    WHERE id = %s
                """, (live_id,))
                incident['viewer_count'] += 1
                
    finally:
        conn.close()
        
    return render_template('live/watch_room.html', incident=incident, comments=comments, video_filename=video_filename)

@live_bp.route('/recording/<filename>')
def serve_recording(filename):
    """Serves the completed stream recording video publicly."""
    return send_from_directory(Config.UPLOAD_FOLDER, filename)


@live_bp.route('/delete-recording/<live_id>', methods=['POST'])
@login_required
@roles_allowed('admin')
def delete_saved_recording(live_id):
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash("Security token expired or invalid.", "danger")
        return redirect(url_for('live_incidents.public_incidents'))

    conn = get_db_connection()
    staged_path = None
    filepath = None
    evidence = None
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT l.saved_video_evidence_id, e.stored_filename, e.sha256_hash
                FROM live_incidents l
                LEFT JOIN evidence e ON e.id = l.saved_video_evidence_id
                WHERE l.id = %s AND l.status = 'completed'
            """, (live_id,))
            evidence = cursor.fetchone()

            if not evidence or not evidence['saved_video_evidence_id'] or not evidence['stored_filename']:
                flash("Saved recording not found.", "warning")
                return redirect(url_for('live_incidents.public_incidents'))

            stored_filename = evidence['stored_filename']
            upload_dir = os.path.abspath(Config.UPLOAD_FOLDER)
            filepath = os.path.abspath(os.path.join(upload_dir, stored_filename))
            if os.path.basename(stored_filename) != stored_filename or os.path.commonpath((upload_dir, filepath)) != upload_dir:
                abort(400, "Invalid recording storage path.")

            if os.path.isfile(filepath):
                staged_path = f"{filepath}.deleting-{secrets.token_hex(8)}"
                os.replace(filepath, staged_path)

            conn.begin()
            cursor.execute("""
                UPDATE live_incidents
                SET saved_video_evidence_id = NULL
                WHERE id = %s AND saved_video_evidence_id = %s
            """, (live_id, evidence['saved_video_evidence_id']))
            if cursor.rowcount != 1:
                raise RuntimeError("Saved recording changed before deletion completed.")

            cursor.execute("""
                INSERT INTO chain_of_custody (evidence_id, user_id, action, description)
                VALUES (%s, %s, 'ADMIN_DELETED', %s)
            """, (
                evidence['saved_video_evidence_id'], session.get('user_id'),
                f"Administrator removed the saved livestream file for {live_id}. Original SHA-256: {evidence['sha256_hash']}."
            ))
        conn.commit()
    except Exception as e:
        conn.rollback()
        if staged_path and os.path.exists(staged_path) and filepath:
            os.replace(staged_path, filepath)
        flash("Could not delete the saved recording. Please try again.", "danger")
        print(f"SAVED RECORDING DELETE ERROR: {e}")
        return redirect(url_for('live_incidents.public_incidents'))
    finally:
        conn.close()

    cleanup_failed = False
    if staged_path and os.path.exists(staged_path):
        try:
            os.remove(staged_path)
        except OSError as e:
            cleanup_failed = True
            print(f"SAVED RECORDING FILE CLEANUP ERROR: {e}")

    log_audit(
        user_id=session.get('user_id'),
        action="LIVESTREAM_RECORDING_DELETED",
        evidence_id=evidence['saved_video_evidence_id'],
        live_incident_id=live_id,
        description=f"Admin removed the saved livestream recording for {live_id}. SHA-256: {evidence['sha256_hash']}."
    )
    if cleanup_failed:
        flash("Recording removed from the public list, but the stored file could not be fully cleaned up.", "warning")
    else:
        flash("Saved recording deleted. The incident and custody history were retained.", "success")
    return redirect(url_for('live_incidents.public_incidents'))


@live_bp.route('/end/<live_id>', methods=['POST'])
@login_required
@roles_allowed('citizen')
def end_stream(live_id):
    user_id = session.get('user_id')
    
    if 'video_evidence' not in request.files:
        flash("End signal requires stream video attachment for preservation.", "danger")
        return redirect(url_for('live_incidents.stream_console', live_id=live_id))
        
    video_file = request.files['video_evidence']
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Check authorization
            cursor.execute("SELECT reporter_id, category FROM live_incidents WHERE id = %s AND status = 'active'", (live_id,))
            incident = cursor.fetchone()
            
            if not incident or incident['reporter_id'] != user_id:
                abort(403)
                
            # Preserve the video file in the vault
            stored_name = f"preserv_{live_id}_{secrets.token_hex(4)}.webm"
            filepath = os.path.join(Config.UPLOAD_FOLDER, stored_name)
            video_file.save(filepath)
            
            file_size = os.path.getsize(filepath)
            sha256 = calculate_sha256(filepath)
            
            evidence_id = generate_evidence_id()
            
            # Save evidence entry
            cursor.execute("""
                INSERT INTO evidence (
                    id, case_id, complaint_id, original_filename, stored_filename,
                    file_type, file_size, sha256_hash, uploaded_by, evidence_source, status
                ) VALUES (%s, NULL, NULL, %s, %s, 'webm', %s, %s, %s, 'livestream', 'potential')
            """, (evidence_id, f"livestream_{live_id}.webm", stored_name, file_size, sha256, user_id))
            
            # Add custody log
            cursor.execute("""
                INSERT INTO chain_of_custody (evidence_id, user_id, action, description)
                VALUES (%s, %s, 'UPLOADED', %s)
            """, (
                evidence_id, user_id,
                f"Livestream video for {live_id} preserved as {stored_name}. Hashed with SHA-256: {sha256}. Status: Potential Digital Evidence - Pending Investigator Verification."
            ))
            
            # Mark stream completed
            cursor.execute("""
                UPDATE live_incidents 
                SET status = 'completed', ended_at = %s, saved_video_evidence_id = %s
                WHERE id = %s
            """, (datetime.now(), evidence_id, live_id))
            
            # Clear viewers
            cursor.execute("DELETE FROM live_viewers WHERE live_incident_id = %s", (live_id,))
            
            # Log audit
            log_audit(
                user_id=user_id,
                action="LIVESTREAM_COMPLETION",
                live_incident_id=live_id,
                evidence_id=evidence_id,
                description=f"Livestream {live_id} completed. Video preserved as evidence {evidence_id}. Hash: {sha256[:16]}..."
            )
            
        flash("Livestream ended and saved successfully. Forensic integrity has been recorded in the Vault.", "success")
        return redirect(url_for('citizen.dashboard'))
        
    except Exception as e:
        flash("Failed to terminate livestream securely.", "danger")
        print(f"END STREAM ERROR: {e}")
        return redirect(url_for('live_incidents.stream_console', live_id=live_id))
    finally:
        conn.close()
