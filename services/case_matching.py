from utils.auth import get_db_connection

def find_and_link_related_cases(case_id, identifier_type, identifier_value):
    """
    Search for other cases that share the same suspect identifier,
    and insert links into the related_cases table.
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Find matching identifiers belonging to suspects in other cases
            cursor.execute("""
                SELECT s.case_id, s.id as suspect_id
                FROM suspect_identifiers i
                JOIN suspects s ON i.suspect_id = s.id
                WHERE i.identifier_type = %s 
                  AND i.identifier_value = %s
                  AND s.case_id != %s
            """, (identifier_type, identifier_value, case_id))
            matches = cursor.fetchall()
            
            for m in matches:
                other_case_id = m['case_id']
                
                # Order case IDs to prevent duplicate linkages (case_1 < case_2)
                case_id_1 = min(case_id, other_case_id)
                case_id_2 = max(case_id, other_case_id)
                
                # Check if linkage already exists
                cursor.execute("""
                    SELECT id FROM related_cases 
                    WHERE case_id_1 = %s AND case_id_2 = %s 
                      AND common_identifier_type = %s 
                      AND common_identifier_value = %s
                """, (case_id_1, case_id_2, identifier_type, identifier_value))
                exists = cursor.fetchone()
                
                if not exists:
                    # Insert potential related case record
                    cursor.execute("""
                        INSERT INTO related_cases (case_id_1, case_id_2, common_identifier_type, common_identifier_value, status)
                        VALUES (%s, %s, %s, %s, 'potential')
                    """, (case_id_1, case_id_2, identifier_type, identifier_value))
                    
                    print(f"LINKED RELATED CASES: {case_id_1} <-> {case_id_2} via {identifier_type}:{identifier_value}")
                    
    except Exception as e:
        print(f"FAILED TO MATCH RELATED CASES: {e}")
    finally:
        conn.close()

def link_initial_complaint_indicators(case_id, contact_indicators):
    """
    Called when a case is created. Parses the comma-separated indicators string
    (e.g., 'email:a@b.com, phone:9876543210'), inserts them as suspect identifiers
    under a default suspect record, and triggers cross-case link matching.
    """
    if not contact_indicators:
        return
        
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Create a default suspect record for the case
            cursor.execute("""
                INSERT INTO suspects (case_id, name, description)
                VALUES (%s, 'Unknown Suspect (Complaint Indicators)', 'Auto-generated suspect profile from initial complaint details.')
            """, (case_id,))
            suspect_id = cursor.lastrowid
            
            # Parse indicators (e.g. 'email:a@b.com, phone:1234')
            parts = [p.strip() for p in contact_indicators.split(',') if p.strip()]
            for part in parts:
                if ':' in part:
                    iden_type, iden_val = part.split(':', 1)
                    iden_type = iden_type.strip()
                    iden_val = iden_val.strip()
                    
                    if iden_type in ['phone', 'email', 'upi', 'username', 'url', 'transaction_id']:
                        # Insert identifier
                        cursor.execute("""
                            INSERT INTO suspect_identifiers (suspect_id, identifier_type, identifier_value)
                            VALUES (%s, %s, %s)
                        """, (suspect_id, iden_type, iden_val))
                        
                        # Match related cases
                        find_and_link_related_cases(case_id, iden_type, iden_val)
    except Exception as e:
        print(f"FAILED TO LINK INITIAL INDICATORS: {e}")
    finally:
        conn.close()
