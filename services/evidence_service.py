import os
from datetime import datetime
from config import Config
from utils.auth import get_db_connection
from utils.security import is_allowed_file, get_secure_upload_name
from services.hash_service import calculate_sha256
from utils.audit import log_audit

def generate_evidence_id():
    """Generates a sequential evidence ID in the format EV-YYYY-NNNNN."""
    current_year = datetime.now().year
    prefix = f"EV-{current_year}-"
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id FROM evidence 
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

def preserve_evidence(file_obj, uploader_id, complaint_id=None, case_id=None, source='citizen', live_incident_id=None):
    """
    Forensics Upload Pipeline:
    Saves file -> Calculates SHA-256 -> Logs Custody -> Audits Action.
    """
    original_filename = file_obj.filename
    if not original_filename or not is_allowed_file(original_filename):
        raise ValueError("Invalid file extension or type not permitted in evidence vault.")
        
    # Generate secure filename
    stored_filename = get_secure_upload_name(original_filename)
    filepath = os.path.join(Config.UPLOAD_FOLDER, stored_filename)
    
    # Save file to filesystem
    file_obj.save(filepath)
    
    # Calculate file size and checksum
    file_size = os.path.getsize(filepath)
    sha256_hash = calculate_sha256(filepath)
    file_type = original_filename.rsplit('.', 1)[1].lower()
    
    evidence_id = generate_evidence_id()
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 1. Insert evidence metadata
            sql = """
            INSERT INTO evidence (
                id, case_id, complaint_id, live_incident_id, original_filename, stored_filename,
                file_type, file_size, sha256_hash, uploaded_by, evidence_source, status
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'potential')
            """
            cursor.execute(sql, (
                evidence_id, case_id, complaint_id, live_incident_id, original_filename, stored_filename,
                file_type, file_size, sha256_hash, uploader_id, source
            ))
            
            # 2. Add custody log entry
            cursor.execute("""
                INSERT INTO chain_of_custody (evidence_id, user_id, action, description)
                VALUES (%s, %s, 'UPLOADED', %s)
            """, (
                evidence_id, uploader_id, 
                f"File {original_filename} preserved as {stored_filename}. SHA-256 hash calculated: {sha256_hash}."
            ))
            
            # 3. Add system audit log entry
            log_audit(
                user_id=uploader_id,
                action="EVIDENCE_PRESERVATION",
                case_id=case_id,
                evidence_id=evidence_id,
                live_incident_id=live_incident_id,
                description=f"Evidence {evidence_id} ({original_filename}) preserved. Hash: {sha256_hash[:16]}..."
            )
            
        return evidence_id
        
    except Exception as e:
        # Cleanup uploaded file if DB write failed to maintain integrity
        if os.path.exists(filepath):
            os.remove(filepath)
        raise e
    finally:
        conn.close()
