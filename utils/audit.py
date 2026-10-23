from flask import request, has_request_context
from utils.auth import get_db_connection

def log_audit(user_id, action, description, case_id=None, evidence_id=None, live_incident_id=None):
    """
    Log an event to the audit_logs table.
    Captures IP address automatically if inside a Flask request context.
    """
    ip_address = '127.0.0.1'
    if has_request_context():
        # Handle reverse proxies (like Cloudflare or Nginx) if needed, fallback to remote_addr
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        # In case of comma-separated list of IPs, get the first one
        if ip_address and ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql = """
            INSERT INTO audit_logs (user_id, action, case_id, evidence_id, live_incident_id, ip_address, description)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (user_id, action, case_id, evidence_id, live_incident_id, ip_address, description))
    except Exception as e:
        # Audit failures must not prevent the original request from completing.
        import sys
        print(f"FAILED TO WRITE AUDIT LOG: {e}", file=sys.stderr)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception as e:
                import sys
                print(f"FAILED TO CLOSE AUDIT DB CONNECTION: {e}", file=sys.stderr)
