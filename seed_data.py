import os
import pymysql
from werkzeug.security import generate_password_hash
from config import Config


def get_seed_password(environment_name, local_default):
    """Use deployment-specific credentials when seeding demo accounts."""
    password = os.environ.get(environment_name)
    if password is None:
        return local_default
    if len(password) < 12 or not any(char.isalpha() for char in password) or not any(char.isdigit() for char in password):
        raise ValueError(f"{environment_name} must be at least 12 characters and contain letters and numbers.")
    return password


def create_folders():
    """Create necessary upload directories if they don't exist."""
    folders = [Config.UPLOAD_FOLDER, Config.LIVE_SNAPSHOTS_FOLDER]
    for folder in folders:
        if not os.path.exists(folder):
            os.makedirs(folder)
            print(f"Created directory: {folder}")

def read_sql_schema(filepath):
    """Read schema file and split into separate statements."""
    with open(filepath, 'r') as f:
        schema_sql = f.read()
    
    # Simple parser to remove SQL comments and split by ';'
    statements = []
    current_statement = []
    
    for line in schema_sql.splitlines():
        trimmed = line.strip()
        if not trimmed or trimmed.startswith('--'):
            continue
        current_statement.append(line)
        if trimmed.endswith(';'):
            statements.append('\n'.join(current_statement))
            current_statement = []
            
    return statements

def seed_database():
    admin_password = get_seed_password('SEED_ADMIN_PASSWORD', 'Admin@123')
    investigator_password = get_seed_password('SEED_INVESTIGATOR_PASSWORD', 'Investigator@123')
    citizen_password = get_seed_password('SEED_CITIZEN_PASSWORD', 'Citizen@123')
    create_folders()
    
    print(f"Connecting to MySQL server at {Config.DB_HOST}...")
    # Connect without specifying database to create it
    conn = pymysql.connect(
        host=Config.DB_HOST,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        autocommit=True
    )
    
    try:
        with conn.cursor() as cursor:
            # Create DB
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {Config.DB_NAME};")
            print(f"Database '{Config.DB_NAME}' verified/created.")
            
        # Re-connect to specific DB
        conn.select_db(Config.DB_NAME)
        
        # Execute schema
        schema_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'schema.sql')
        sql_statements = read_sql_schema(schema_path)
        
        print("Executing schema.sql...")
        with conn.cursor() as cursor:
            # Turn off foreign key checks temporarily to clear data cleanly if reseeding
            cursor.execute("SET FOREIGN_KEY_CHECKS = 0;")
            
            # Drop existing tables to ensure a clean re-run of seeds
            tables = [
                'audit_logs', 'investigation_leads', 'comment_flags', 'comments',
                'live_viewers', 'live_incidents', 'related_cases', 'suspect_identifiers',
                'suspects', 'case_updates', 'case_messages', 'investigation_notes', 'chain_of_custody',
                'awareness_scams',
                'evidence_access_logs', 'evidence', 'investigators', 'cases', 'complaints', 'users'
            ]
            for table in tables:
                cursor.execute(f"DROP TABLE IF EXISTS {table};")
                
            cursor.execute("SET FOREIGN_KEY_CHECKS = 1;")
            
            # Execute each table creation statement
            for sql in sql_statements:
                if sql.strip():
                    cursor.execute(sql)
                    
        print("Schema loaded successfully. Seeding data...")
        
        # Insert users
        users = [
            {
                'username': 'admin1',
                'email': 'admin@forensics.local',
                'password_hash': generate_password_hash(admin_password),
                'phone': '+919999999901',
                'fullname': 'Super Admin Officer',
                'role': 'admin'
            },
            {
                'username': 'investigator1',
                'email': 'investigator1@forensics.local',
                'password_hash': generate_password_hash(investigator_password),
                'phone': '+919999999902',
                'fullname': 'Inspector Rajesh Kumar',
                'role': 'investigator'
            },
            {
                'username': 'investigator2',
                'email': 'investigator2@forensics.local',
                'password_hash': generate_password_hash(investigator_password),
                'phone': '+919999999903',
                'fullname': 'Sub-Inspector Anjali Sharma',
                'role': 'investigator'
            },
            {
                'username': 'citizen1',
                'email': 'citizen1@forensics.local',
                'password_hash': generate_password_hash(citizen_password),
                'phone': '+919876543210',
                'fullname': 'Fictional Citizen A',
                'role': 'citizen'
            },
            {
                'username': 'citizen2',
                'email': 'citizen2@forensics.local',
                'password_hash': generate_password_hash(citizen_password),
                'phone': '+919876543211',
                'fullname': 'Fictional Citizen B',
                'role': 'citizen'
            }
        ]
        
        user_ids = {}
        with conn.cursor() as cursor:
            insert_user_sql = """
            INSERT INTO users (username, email, password_hash, phone, fullname, role)
            VALUES (%(username)s, %(email)s, %(password_hash)s, %(phone)s, %(fullname)s, %(role)s)
            """
            for user in users:
                cursor.execute(insert_user_sql, user)
                user_ids[user['username']] = cursor.lastrowid
                
        print(f"Users seeded: {list(user_ids.keys())}")
        
        # Insert investigators metadata
        investigators = [
            {
                'user_id': user_ids['investigator1'],
                'rank': 'Senior Cyber Investigator',
                'department': 'Digital Forensics & Malware Analysis Unit',
                'assigned_cases_count': 1
            },
            {
                'user_id': user_ids['investigator2'],
                'rank': 'Junior Cyber Investigator',
                'department': 'Mobile Forensics Unit',
                'assigned_cases_count': 0
            }
        ]
        
        with conn.cursor() as cursor:
            insert_inv_sql = """
            INSERT INTO investigators (user_id, rank, department, assigned_cases_count)
            VALUES (%(user_id)s, %(rank)s, %(department)s, %(assigned_cases_count)s)
            """
            for inv in investigators:
                cursor.execute(insert_inv_sql, inv)
                
        print("Investigators meta-details seeded.")
        
        # Seed fictional complaints, cases, and updates to demonstrate the system
        # Scenario: Phishing attack with a UPI ID & social media harassment
        complaints = [
            {
                'id': 'CR-2026-00001',
                'citizen_id': user_ids['citizen1'],
                'category': 'Financial Cyber Fraud',
                'incident_date': '2026-08-18',
                'incident_time': '10:30:00',
                'location': 'Mumbai, Maharashtra',
                'description': 'Received a phishing link via SMS claiming my bank account was blocked. When I clicked it, it redirected to a fake bank website and I lost Rs. 50,000 via a fake UPI transaction. The transaction was sent to upi-fraudster@okaxis. Also got threatening WhatsApp messages from +919876500123.',
                'victim_info': 'Fictional Citizen A, Phone: +919876543210',
                'suspect_info': 'Threatening messages sender on phone: +919876500123. UPI ID: upi-fraudster@okaxis',
                'contact_indicators': 'upi-fraudster@okaxis, +919876500123',
                'financial_loss': 50000.00,
                'additional_info': 'Transaction ID was TXN987213890',
                'reporting_mode': 'identified',
                'status': 'accepted',
                'priority': 'HIGH',
                'priority_reason': 'High financial loss (Rs. 50,000) and active suspect indicators (phone, UPI ID).',
                'ai_category': 'Financial Cyber Fraud',
                'ai_priority': 'HIGH',
                'ai_missing_info': 'Bank account statement or transaction proof screenshots.',
                'ai_recommended_evidence': 'Screenshots of SMS message, fake website, and UPI transaction receipt.',
                'ai_summary': 'Citizen A was defrauded of Rs. 50,000 via a fake banking site, sending money to UPI ID: upi-fraudster@okaxis. Suspect sent threatening messages via phone +919876500123.'
            },
            {
                'id': 'CR-2026-00002',
                'citizen_id': user_ids['citizen2'],
                'category': 'Cyber Harassment',
                'incident_date': '2026-08-19',
                'incident_time': '09:00:00',
                'location': 'Delhi',
                'description': 'Anonymous profile on Instagram is posting morphed photos of me. They are calling me from +919876500123 and blackmailing me for money. The email they sent from is blackmailer.crime@gmail.com.',
                'victim_info': 'Fictional Citizen B',
                'suspect_info': 'Instagram handle: @cyberstalker_99. Phone number: +919876500123. Email: blackmailer.crime@gmail.com',
                'contact_indicators': '+919876500123, blackmailer.crime@gmail.com',
                'financial_loss': 0.00,
                'additional_info': 'Suspect threatening to leak photos to friends.',
                'reporting_mode': 'anonymous',
                'status': 'under_review',
                'priority': 'CRITICAL',
                'priority_reason': 'Stalking, blackmail, extortion threat, and vulnerable target indicators.',
                'ai_category': 'Cyber Harassment',
                'ai_priority': 'CRITICAL',
                'ai_missing_info': 'Profile link of Instagram account, copies of blackmail emails.',
                'ai_recommended_evidence': 'Screenshots of Instagram direct messages, email headers of blackmailer.crime@gmail.com.',
                'ai_summary': 'Anonymous complaint of stalking and extortion. Stalker is blackmailing victim using phone +919876500123 and email blackmailer.crime@gmail.com.'
            }
        ]
        
        with conn.cursor() as cursor:
            insert_comp_sql = """
            INSERT INTO complaints (id, citizen_id, category, incident_date, incident_time, location, description, victim_info, suspect_info, contact_indicators, financial_loss, additional_info, reporting_mode, status, priority, priority_reason, ai_category, ai_priority, ai_missing_info, ai_recommended_evidence, ai_summary)
            VALUES (%(id)s, %(citizen_id)s, %(category)s, %(incident_date)s, %(incident_time)s, %(location)s, %(description)s, %(victim_info)s, %(suspect_info)s, %(contact_indicators)s, %(financial_loss)s, %(additional_info)s, %(reporting_mode)s, %(status)s, %(priority)s, %(priority_reason)s, %(ai_category)s, %(ai_priority)s, %(ai_missing_info)s, %(ai_recommended_evidence)s, %(ai_summary)s)
            """
            for comp in complaints:
                cursor.execute(insert_comp_sql, comp)
                
        print("Complaints seeded.")
        
        # Create Case for the first complaint (accepted)
        case = {
            'id': 'CASE-2026-00001',
            'complaint_id': 'CR-2026-00001',
            'investigator_id': user_ids['investigator1'],
            'status': 'under_investigation'
        }
        
        with conn.cursor() as cursor:
            insert_case_sql = """
            INSERT INTO cases (id, complaint_id, investigator_id, status)
            VALUES (%(id)s, %(complaint_id)s, %(investigator_id)s, %(status)s)
            """
            cursor.execute(insert_case_sql, case)
            
        print("Active case seeded.")
        
        # Seed case updates (timeline)
        updates = [
            {
                'case_id': 'CASE-2026-00001',
                'status': 'assigned',
                'update_message': 'Case created and assigned to Inspector Rajesh Kumar.'
            },
            {
                'case_id': 'CASE-2026-00001',
                'status': 'under_investigation',
                'update_message': 'Investigation initiated. Reviewing bank transaction details.'
            }
        ]
        
        with conn.cursor() as cursor:
            insert_update_sql = """
            INSERT INTO case_updates (case_id, status, update_message)
            VALUES (%(case_id)s, %(status)s, %(update_message)s)
            """
            for update in updates:
                cursor.execute(insert_update_sql, update)
                
        print("Case timelines seeded.")
        
        # Seed suspects and indicators for related case checking
        with conn.cursor() as cursor:
            # Add suspect A
            cursor.execute("""
            INSERT INTO suspects (case_id, name, description)
            VALUES ('CASE-2026-00001', 'Unknown Fraudster', 'Operates phishing bank page and harassing phone line')
            """)
            suspect_id = cursor.lastrowid
            
            # Add suspect identifiers
            identifiers = [
                {'suspect_id': suspect_id, 'type': 'phone', 'value': '+919876500123'},
                {'suspect_id': suspect_id, 'type': 'upi', 'value': 'upi-fraudster@okaxis'}
            ]
            for iden in identifiers:
                cursor.execute("""
                INSERT INTO suspect_identifiers (suspect_id, identifier_type, identifier_value)
                VALUES (%s, %s, %s)
                """, (iden['suspect_id'], iden['type'], iden['value']))
                
        print("Suspect intelligence seeded.")
        
        # Write initial Audit Log entries
        audit_entries = [
            {
                'user_id': user_ids['citizen1'],
                'action': 'Complaint creation',
                'case_id': None,
                'evidence_id': None,
                'live_incident_id': None,
                'ip_address': '127.0.0.1',
                'description': 'Citizen created complaint CR-2026-00001 regarding Financial Cyber Fraud.'
            },
            {
                'user_id': user_ids['admin1'],
                'action': 'Case assignment',
                'case_id': 'CASE-2026-00001',
                'evidence_id': None,
                'live_incident_id': None,
                'ip_address': '127.0.0.1',
                'description': 'Admin approved complaint CR-2026-00001, created case CASE-2026-00001, and assigned Investigator Rajesh Kumar.'
            }
        ]
        
        with conn.cursor() as cursor:
            insert_audit_sql = """
            INSERT INTO audit_logs (user_id, action, case_id, evidence_id, live_incident_id, ip_address, description)
            VALUES (%(user_id)s, %(action)s, %(case_id)s, %(evidence_id)s, %(live_incident_id)s, %(ip_address)s, %(description)s)
            """
            for audit in audit_entries:
                cursor.execute(insert_audit_sql, audit)
                
        print("Audit logs initialized.")
        print("Database verification, schema installation, and seeding completed successfully!")
        
    finally:
        conn.close()

if __name__ == '__main__':
    seed_database()
