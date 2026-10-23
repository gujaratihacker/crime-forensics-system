from flask import Blueprint, request, redirect, url_for, flash, session, abort, send_from_directory, jsonify
from utils.auth import login_required, get_db_connection, roles_allowed
from utils.security import validate_csrf_token, sanitize_string
from services.evidence_service import preserve_evidence
from services.hash_service import calculate_sha256
from utils.audit import log_audit
from config import Config
import os

evidence_bp = Blueprint('evidence', __name__, url_prefix='/evidence')

@evidence_bp.route('/upload', methods=['POST'])
@login_required
def upload():
    # CSRF Check
    token = request.form.get('csrf_token')
    if not validate_csrf_token(token):
        flash("CSRF token verification failed.", "danger")
        return redirect(request.referrer or url_for('citizen.dashboard'))
        
    complaint_id = sanitize_string(request.form.get('complaint_id'))
    case_id = sanitize_string(request.form.get('case_id'))
    live_incident_id = sanitize_string(request.form.get('live_incident_id'))
    
    if not complaint_id and not live_incident_id:
        flash("Reference ID is required to upload files.", "danger")
        return redirect(request.referrer or url_for('citizen.dashboard'))
        
    if 'evidence_file' not in request.files:
        flash("No file selected.", "danger")
        return redirect(request.referrer or url_for('citizen.dashboard'))
        
    file = request.files['evidence_file']
    if file.filename == '':
        flash("No file selected.", "danger")
        return redirect(request.referrer or url_for('citizen.dashboard'))
        
    user_id = session.get('user_id')
    user_role = session.get('role')
    source = 'citizen' if user_role == 'citizen' else 'viewer'
    
    try:
        # Save and hash evidence
        evidence_id = preserve_evidence(
            file_obj=file,
            uploader_id=user_id,
            complaint_id=complaint_id if complaint_id else None,
            case_id=case_id if case_id else None,
            source=source,
            live_incident_id=live_incident_id if live_incident_id else None
        )
        flash(f"Forensic file preserved. Vault reference ID: {evidence_id}", "success")
    except ValueError as ve:
        flash(str(ve), "danger")
    except Exception as e:
        flash("Evidence upload failed due to a system error.", "danger")
        print(f"EVIDENCE UPLOAD ERROR: {e}")
        
    return redirect(request.referrer or url_for('citizen.dashboard'))

@evidence_bp.route('/download/<evidence_id>')
@login_required
def download(evidence_id):
    user_id = session.get('user_id')
    user_role = session.get('role')
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Fetch metadata
            cursor.execute("SELECT * FROM evidence WHERE id = %s", (evidence_id,))
            file = cursor.fetchone()
            
            if not file:
                abort(404, "Evidence file not found.")
                
            # Authorization check: citizens can only download their own uploads
            if user_role == 'citizen' and file['uploaded_by'] != user_id:
                abort(403, "You do not have credentials to download this file.")
                
            # Log custody
            cursor.execute("""
                INSERT INTO chain_of_custody (evidence_id, user_id, action, description)
                VALUES (%s, %s, 'ACCESSED', %s)
            """, (evidence_id, user_id, f"File {file['original_filename']} downloaded/viewed by user ID {user_id}."))
            
            log_audit(
                user_id=user_id,
                action="EVIDENCE_DOWNLOAD",
                case_id=file['case_id'],
                evidence_id=evidence_id,
                description=f"Evidence {evidence_id} ({file['original_filename']}) was accessed/downloaded."
            )
            
            # Serve file from directory securely
            return send_from_directory(Config.UPLOAD_FOLDER, file['stored_filename'], as_attachment=True, download_name=file['original_filename'])
            
    finally:
        conn.close()

@evidence_bp.route('/verify/<evidence_id>', methods=['POST'])
@login_required
@roles_allowed('investigator', 'admin')
def verify(evidence_id):
    # CSRF Check
    token = request.form.get('csrf_token')
    if not validate_csrf_token(token):
        flash("CSRF token verification failed.", "danger")
        return redirect(request.referrer or url_for('investigator.dashboard'))
        
    user_id = session.get('user_id')
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Fetch metadata
            cursor.execute("SELECT * FROM evidence WHERE id = %s", (evidence_id,))
            file = cursor.fetchone()
            
            if not file:
                flash("Evidence file not found.", "danger")
                return redirect(request.referrer or url_for('investigator.dashboard'))
                
            filepath = os.path.join(Config.UPLOAD_FOLDER, file['stored_filename'])
            
            if not os.path.exists(filepath):
                # File missing on disk
                cursor.execute("UPDATE evidence SET status = 'failed_integrity' WHERE id = %s", (evidence_id,))
                
                # Chain of Custody entry
                cursor.execute("""
                    INSERT INTO chain_of_custody (evidence_id, user_id, action, description)
                    VALUES (%s, %s, 'VERIFY_FAILED', 'File missing from server filesystem disk!')
                """, (evidence_id, user_id))
                
                log_audit(
                    user_id=user_id,
                    action="EVIDENCE_INTEGRITY_FAIL",
                    case_id=file['case_id'],
                    evidence_id=evidence_id,
                    description=f"Integrity check failed for evidence {evidence_id}. File missing from storage."
                )
                
                flash("INTEGRITY CHECK FAILED! File is missing from filesystem.", "danger")
                return redirect(request.referrer or url_for('investigator.dashboard'))
                
            # Re-calculate hash
            current_hash = calculate_sha256(filepath)
            
            if current_hash == file['sha256_hash']:
                # Hash match!
                cursor.execute("UPDATE evidence SET status = 'verified' WHERE id = %s", (evidence_id,))
                
                cursor.execute("""
                    INSERT INTO chain_of_custody (evidence_id, user_id, action, description)
                    VALUES (%s, %s, 'VERIFIED', %s)
                """, (evidence_id, user_id, f"Integrity check successful. Current SHA-256 ({current_hash}) matches original value."))
                
                log_audit(
                    user_id=user_id,
                    action="EVIDENCE_INTEGRITY_SUCCESS",
                    case_id=file['case_id'],
                    evidence_id=evidence_id,
                    description=f"Integrity verified for evidence {evidence_id}. SHA-256: {current_hash[:16]}..."
                )
                
                flash(f"INTEGRITY VERIFIED: File '{file['original_filename']}' checksum matches original hash.", "success")
            else:
                # Hash changed!
                cursor.execute("UPDATE evidence SET status = 'failed_integrity' WHERE id = %s", (evidence_id,))
                
                cursor.execute("""
                    INSERT INTO chain_of_custody (evidence_id, user_id, action, description)
                    VALUES (%s, %s, 'VERIFY_FAILED', %s)
                """, (evidence_id, user_id, f"INTEGRITY VIOLATION DETECTED! Current SHA-256: {current_hash}. Original SHA-256: {file['sha256_hash']}."))
                
                log_audit(
                    user_id=user_id,
                    action="EVIDENCE_INTEGRITY_VIOLATION",
                    case_id=file['case_id'],
                    evidence_id=evidence_id,
                    description=f"CRITICAL: Integrity violation on {evidence_id}. Original hash {file['sha256_hash'][:8]} != current hash {current_hash[:8]}."
                )
                
                flash("INTEGRITY CHECK FAILED! File has been altered or corrupted. Violation logged in custody timeline.", "danger")
                
    except Exception as e:
        flash("Failed to run integrity verify.", "danger")
        print(f"VERIFY ERROR: {e}")
    finally:
        conn.close()
        
    return redirect(request.referrer or url_for('investigator.dashboard'))

@evidence_bp.route('/chain/<evidence_id>')
@login_required
def chain(evidence_id):
    """API endpoint to fetch Chain of Custody logs for a specific evidence item."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT c.action, c.description, c.timestamp, u.fullname as user_name
                FROM chain_of_custody c
                LEFT JOIN users u ON c.user_id = u.id
                WHERE c.evidence_id = %s
                ORDER BY c.timestamp ASC
            """, (evidence_id,))
            logs = cursor.fetchall()
            
            # Format timestamp strings
            for log in logs:
                log['timestamp'] = log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                
            return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()
