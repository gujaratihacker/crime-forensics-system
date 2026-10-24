import os
import sys
import unittest
from io import BytesIO
from unittest.mock import MagicMock, patch
from flask import session
from werkzeug.security import generate_password_hash, check_password_hash

# Add parent directory to path so we can import app modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app
from services.hash_service import calculate_sha256
from services.ai_analysis import analyze_complaint

class ForensicsAppTestCase(unittest.TestCase):
    def setUp(self):
        # Configure app for testing
        app.config['TESTING'] = True
        self.client = app.test_client()
        self.auth_role_override = None
        self.auth_user_exists = True
        self.auth_connection = MagicMock()
        auth_cursor = self.auth_connection.cursor.return_value.__enter__.return_value
        auth_cursor.fetchone.side_effect = self._authenticated_user
        self.auth_db_patcher = patch('utils.auth.get_db_connection', return_value=self.auth_connection)
        self.auth_db_patcher.start()
        self.addCleanup(self.auth_db_patcher.stop)

    def _authenticated_user(self):
        if not self.auth_user_exists or not session.get('user_id'):
            return None
        return {'role': self.auth_role_override or session.get('role')}
        
    def test_password_hashing(self):
        """Test secure password hashing and verification."""
        password = "SecurePassword@123"
        hash_val = generate_password_hash(password)
        
        # Verify hash is not plaintext
        self.assertNotEqual(password, hash_val)
        
        # Verify check works
        self.assertTrue(check_password_hash(hash_val, password))
        self.assertFalse(check_password_hash(hash_val, "WrongPassword@123"))

    def test_registration_preserves_values_and_shows_email_error_inline(self):
        """Invalid registration keeps entered non-sensitive values and marks the email field."""
        with self.client.session_transaction() as test_session:
            test_session['csrf_token'] = 'test-token'

        response = self.client.post('/register', data={
            'csrf_token': 'test-token',
            'fullname': 'Ankit Example',
            'username': 'ankit_example',
            'email': 'not-an-email',
            'phone': '+919876543210',
            'password': 'SecurePassword123',
            'confirm_password': 'SecurePassword123',
            'doc_type': 'Aadhar Card',
            'verification_file': (BytesIO(b'test document'), 'proof.png')
        })

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'value="Ankit Example"', response.data)
        self.assertIn(b'value="ankit_example"', response.data)
        self.assertIn(b'value="not-an-email"', response.data)
        self.assertIn(b'value="+919876543210"', response.data)
        self.assertIn(b'id="emailError">Please enter a valid email address.', response.data)
        self.assertNotIn(b'class="alert alert-danger"', response.data)
        self.assertNotIn(b'value="SecurePassword123"', response.data)

    def test_registration_shows_password_mismatch_at_confirmation_field(self):
        """Password mismatch is displayed beside confirmation without losing form values."""
        with self.client.session_transaction() as test_session:
            test_session['csrf_token'] = 'test-token'

        response = self.client.post('/register', data={
            'csrf_token': 'test-token',
            'fullname': 'Ankit Example',
            'username': 'ankit_example',
            'email': 'ankit@example.com',
            'phone': '+919876543210',
            'password': 'SecurePassword123',
            'confirm_password': 'DifferentPassword123',
            'doc_type': 'PAN Card',
            'verification_file': (BytesIO(b'test document'), 'proof.png')
        })

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'value="ankit@example.com"', response.data)
        self.assertIn(b'id="confirmPasswordError">Passwords do not match.', response.data)
        self.assertNotIn(b'value="SecurePassword123"', response.data)
        self.assertNotIn(b'value="DifferentPassword123"', response.data)

    def test_investigator_only_sees_assigned_social_media_reports(self):
        """Investigator report listing is filtered to their assigned cases."""
        with self.client.session_transaction() as test_session:
            test_session.update({'user_id': 7, 'role': 'investigator'})

        with patch('routes.social_media_crimes.get_db_connection') as get_connection:
            cursor = get_connection.return_value.cursor.return_value.__enter__.return_value
            cursor.fetchall.return_value = [{
                'complaint_id': 'CMP-2026-00001',
                'created_at': '2026-10-23',
                'status': 'submitted',
                'priority': 'LOW',
                'description': 'Social report details',
                'reporting_mode': 'identified',
                'reporter_name': 'Test Citizen',
                'platform': 'Instagram',
                'crime_type': 'Fake profile',
                'profile_url': 'https://example.com/profile',
                'case_id': 'CASE-2026-00001',
                'case_status': 'assigned',
                'investigator_name': 'Test Investigator'
            }]

            response = self.client.get('/social-media-crimes/report')
            executed_query, query_params = cursor.execute.call_args[0]

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Social report details', response.data)
        self.assertIn('WHERE ca.investigator_id = %s', executed_query)
        self.assertEqual(query_params, (7,))

    def test_admin_can_view_all_social_media_reports(self):
        """Administrator report list only queries reports with social-media metadata."""
        with self.client.session_transaction() as test_session:
            test_session.update({'user_id': 1, 'role': 'admin'})

        with patch('routes.social_media_crimes.get_db_connection') as get_connection:
            cursor = get_connection.return_value.cursor.return_value.__enter__.return_value
            cursor.fetchall.return_value = []

            response = self.client.get('/social-media-crimes/report')
            executed_query = cursor.execute.call_args[0][0]

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'All submitted social media crime reports.', response.data)
        self.assertIn('FROM social_media_complaints sm', executed_query)
        self.assertNotIn('WHERE ca.investigator_id', executed_query)

    def test_staff_cannot_submit_social_media_report(self):
        """Staff roles can view reports but cannot submit citizen reports."""
        with self.client.session_transaction() as test_session:
            test_session.update({'user_id': 1, 'role': 'admin'})

        with patch('routes.social_media_crimes.get_db_connection') as get_connection:
            response = self.client.post('/social-media-crimes/report')

        self.assertEqual(response.status_code, 403)
        get_connection.assert_not_called()

    def test_citizen_and_assigned_investigator_can_message_case(self):
        """Both authorized case participants can send shared messages."""
        participants = (
            ('citizen', 10, '/complaints/detail/CR-2026-00001'),
            ('investigator', 20, '/investigator/case/CASE-2026-00001')
        )
        for role, user_id, expected_location in participants:
            with self.subTest(role=role):
                with self.client.session_transaction() as test_session:
                    test_session.update({
                        'user_id': user_id,
                        'role': role,
                        'csrf_token': 'test-token'
                    })

                with patch('routes.complaints.get_db_connection') as get_connection, \
                        patch('routes.complaints.ensure_case_messages_table') as ensure_table, \
                        patch('routes.complaints.log_audit') as log_audit:
                    cursor = get_connection.return_value.cursor.return_value.__enter__.return_value
                    cursor.fetchone.return_value = {
                        'complaint_id': 'CR-2026-00001',
                        'investigator_id': 20,
                        'citizen_id': 10
                    }
                    response = self.client.post(
                        '/complaints/case/CASE-2026-00001/messages',
                        data={
                            'csrf_token': 'test-token',
                            'complaint_id': 'CR-2026-00001',
                            'message': 'Please share a case update.'
                        }
                    )

                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.location, expected_location)
                ensure_table.assert_called_once()
                log_audit.assert_called_once()
                self.assertEqual(cursor.execute.call_count, 2)
                insert_sql, insert_params = cursor.execute.call_args[0]
                self.assertIn('INSERT INTO case_messages', insert_sql)
                self.assertEqual(insert_params, ('CASE-2026-00001', user_id, 'Please share a case update.'))

    def test_citizen_cannot_message_another_reporters_case(self):
        """A citizen cannot send a message on a case they do not own."""
        with self.client.session_transaction() as test_session:
            test_session.update({
                'user_id': 11,
                'role': 'citizen',
                'csrf_token': 'test-token'
            })

        with patch('routes.complaints.get_db_connection') as get_connection, \
                patch('routes.complaints.ensure_case_messages_table') as ensure_table:
            cursor = get_connection.return_value.cursor.return_value.__enter__.return_value
            cursor.fetchone.return_value = {
                'complaint_id': 'CR-2026-00001',
                'investigator_id': 20,
                'citizen_id': 10
            }
            response = self.client.post(
                '/complaints/case/CASE-2026-00001/messages',
                data={
                    'csrf_token': 'test-token',
                    'complaint_id': 'CR-2026-00001',
                    'message': 'This should be rejected.'
                }
            )

        self.assertEqual(response.status_code, 403)
        ensure_table.assert_not_called()
        self.assertEqual(cursor.execute.call_count, 1)

    def test_evidence_hashing(self):
        """Test SHA-256 file hashing correctness."""
        test_filepath = "test_evidence_file.txt"
        with open(test_filepath, "w") as f:
            f.write("Forensic evidence block content.")
            
        try:
            hash_val = calculate_sha256(test_filepath)
            expected_hash = "9e18c0e66e0ca5ae54c4ad8d03b3cd554c57d3432c72ef49a06655d846ce7497"
            self.assertEqual(hash_val, expected_hash)
        finally:
            if os.path.exists(test_filepath):
                os.remove(test_filepath)

    def test_integrity_verification_failure(self):
        """Test that modifying a file changes its SHA-256 hash (integrity violation check)."""
        test_filepath = "tamper_proof_file.txt"
        with open(test_filepath, "w") as f:
            f.write("Original content log.")
            
        try:
            original_hash = calculate_sha256(test_filepath)
            
            # Modify/Tamper with the file
            with open(test_filepath, "w") as f:
                f.write("Tampered content log.")
                
            tampered_hash = calculate_sha256(test_filepath)
            
            # Assert that the hash has changed, triggering integrity alarm
            self.assertNotEqual(original_hash, tampered_hash)
            print(f"Tamper Check: Original Hash ({original_hash[:8]}...) != Tampered Hash ({tampered_hash[:8]}...) -> SUCCESS")
        finally:
            if os.path.exists(test_filepath):
                os.remove(test_filepath)

    def test_rbac_boundaries(self):
        """Verify role boundaries: citizen or guest cannot view investigator/admin views."""
        # Test anonymous access to admin
        response = self.client.get('/admin/dashboard', follow_redirects=True)
        # Should redirect to login page
        self.assertIn(b"Authentication required", response.data)
        
        # Test anonymous access to investigator
        response2 = self.client.get('/investigator/dashboard', follow_redirects=True)
        self.assertIn(b"Authentication required", response2.data)

    def test_citizen_cannot_delete_saved_recordings(self):
        """Saved recording deletion is restricted to administrators."""
        with self.client.session_transaction() as test_session:
            test_session.update({
                'user_id': 2,
                'role': 'citizen',
                'csrf_token': 'test-token'
            })

        response = self.client.post('/live/delete-recording/LIVE-2026-00003', data={
            'csrf_token': 'test-token'
        })

        self.assertEqual(response.status_code, 403)

    def test_admin_investigator_creation_rejects_invalid_email(self):
        """Reject malformed investigator email before attempting a database write."""
        with self.client.session_transaction() as test_session:
            test_session.update({
                'user_id': 1,
                'role': 'admin',
                'csrf_token': 'test-token'
            })

        response = self.client.post('/admin/investigators/add', data={
            'csrf_token': 'test-token',
            'fullname': 'Test Investigator',
            'username': 'test_investigator',
            'email': 'not-an-email',
            'phone': '1234567890',
            'password': 'Password123'
        })

        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as test_session:
            self.assertEqual(test_session['_flashes'][-1][1], 'Enter a valid email address.')

    def test_admin_user_list_shows_investigator_accounts(self):
        """Administrators can view account and investigator profile details."""
        with self.client.session_transaction() as test_session:
            test_session.update({'user_id': 1, 'role': 'admin'})

        with patch('routes.admin.get_db_connection') as get_connection:
            cursor = get_connection.return_value.cursor.return_value.__enter__.return_value
            cursor.fetchall.return_value = [{
                'id': 2,
                'username': 'investigator1',
                'email': 'investigator1@example.com',
                'phone': '1234567890',
                'fullname': 'Test Investigator',
                'role': 'investigator',
                'created_at': None,
                'rank': 'Senior Detective',
                'department': 'Cyber Crime Unit',
                'assigned_cases_count': 1
            }]

            response = self.client.get('/admin/users')
            query = cursor.execute.call_args[0][0]

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Test Investigator', response.data)
        self.assertIn(b'Senior Detective', response.data)
        self.assertIn('LEFT JOIN investigators', query)
        self.assertNotIn('password_hash', query)

    def test_admin_cannot_create_account_with_invalid_role(self):
        """Account creation accepts only the roles supported by the application."""
        with self.client.session_transaction() as test_session:
            test_session.update({'user_id': 1, 'role': 'admin', 'csrf_token': 'test-token'})

        with patch('routes.admin.get_db_connection') as get_connection:
            response = self.client.post('/admin/users/add', data={
                'csrf_token': 'test-token',
                'fullname': 'Test User',
                'username': 'test_user',
                'email': 'test@example.com',
                'phone': '1234567890',
                'password': 'Password123',
                'role': 'superuser'
            })

        self.assertEqual(response.status_code, 302)
        get_connection.assert_not_called()
        with self.client.session_transaction() as test_session:
            self.assertEqual(test_session['_flashes'][-1][1], 'Select a valid account role.')

    def test_admin_can_create_investigator_account(self):
        """Creating an investigator also creates the matching investigator profile."""
        with self.client.session_transaction() as test_session:
            test_session.update({'user_id': 1, 'role': 'admin', 'csrf_token': 'test-token'})

        with patch('routes.admin.get_db_connection') as get_connection, \
                patch('routes.admin.log_audit') as log_audit:
            conn = get_connection.return_value
            cursor = conn.cursor.return_value.__enter__.return_value
            cursor.fetchone.return_value = None
            cursor.lastrowid = 42

            response = self.client.post('/admin/users/add', data={
                'csrf_token': 'test-token',
                'fullname': 'Test Investigator',
                'username': 'test_investigator',
                'email': 'investigator@example.com',
                'phone': '1234567890',
                'password': 'Password123',
                'role': 'investigator',
                'rank': 'Senior Detective',
                'department': 'Cyber Crime Unit'
            })

        self.assertEqual(response.status_code, 302)
        queries = [call.args[0] for call in cursor.execute.call_args_list]
        self.assertTrue(any('INSERT INTO users' in query for query in queries))
        self.assertTrue(any('INSERT INTO investigators' in query for query in queries))
        self.assertEqual(cursor.execute.call_args_list[-1].args[1], (42, 'Senior Detective', 'Cyber Crime Unit'))
        conn.commit.assert_called_once()
        log_audit.assert_called_once()

    def test_admin_can_promote_user_to_investigator(self):
        """Promoting an account creates its investigator profile and updates its role."""
        with self.client.session_transaction() as test_session:
            test_session.update({'user_id': 1, 'role': 'admin', 'csrf_token': 'test-token'})

        with patch('routes.admin.get_db_connection') as get_connection, \
                patch('routes.admin.log_audit') as log_audit:
            conn = get_connection.return_value
            cursor = conn.cursor.return_value.__enter__.return_value
            cursor.fetchone.side_effect = [
                {'id': 2, 'username': 'test_user', 'role': 'citizen'},
                None
            ]

            response = self.client.post('/admin/users/2/role', data={
                'csrf_token': 'test-token',
                'role': 'investigator'
            })

        self.assertEqual(response.status_code, 302)
        queries = [call.args[0] for call in cursor.execute.call_args_list]
        self.assertTrue(any('INSERT INTO investigators' in query for query in queries))
        self.assertTrue(any('UPDATE users SET role' in query for query in queries))
        conn.commit.assert_called_once()
        log_audit.assert_called_once()

    def test_admin_cannot_change_own_role(self):
        """An administrator cannot lock themselves out of administration."""
        with self.client.session_transaction() as test_session:
            test_session.update({'user_id': 1, 'role': 'admin', 'csrf_token': 'test-token'})

        with patch('routes.admin.get_db_connection') as get_connection:
            response = self.client.post('/admin/users/1/role', data={
                'csrf_token': 'test-token',
                'role': 'citizen'
            })

        self.assertEqual(response.status_code, 302)
        get_connection.assert_not_called()
        with self.client.session_transaction() as test_session:
            self.assertEqual(test_session['_flashes'][-1][1], 'You cannot change your own account role.')

    def test_admin_permissions_use_current_database_role(self):
        """A role downgrade takes effect for the next request, even with an old session cookie."""
        with self.client.session_transaction() as test_session:
            test_session.update({'user_id': 1, 'role': 'admin'})
        self.auth_role_override = 'citizen'

        with patch('routes.admin.get_db_connection') as get_connection:
            response = self.client.get('/admin/users')

        self.assertEqual(response.status_code, 403)
        get_connection.assert_not_called()
        with self.client.session_transaction() as test_session:
            self.assertEqual(test_session['role'], 'citizen')

    def test_removed_account_session_is_invalidated(self):
        """A removed account cannot keep using protected routes with an existing session."""
        with self.client.session_transaction() as test_session:
            test_session.update({'user_id': 1, 'role': 'admin'})
        self.auth_user_exists = False

        response = self.client.get('/admin/users')

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, '/login')
        with self.client.session_transaction() as test_session:
            self.assertNotIn('user_id', test_session)

    def test_admin_cannot_delete_user_with_assigned_cases(self):
        """User deletion must not detach an investigator from assigned cases."""
        with self.client.session_transaction() as test_session:
            test_session.update({'user_id': 1, 'role': 'admin', 'csrf_token': 'test-token'})

        with patch('routes.admin.get_db_connection') as get_connection:
            cursor = get_connection.return_value.cursor.return_value.__enter__.return_value
            cursor.fetchone.side_effect = [
                {'id': 2, 'username': 'investigator1', 'role': 'investigator'},
                {'count': 1}
            ]

            response = self.client.post('/admin/users/2/delete', data={'csrf_token': 'test-token'})

        self.assertEqual(response.status_code, 302)
        executed_queries = [call.args[0] for call in cursor.execute.call_args_list]
        self.assertFalse(any(query.startswith('DELETE FROM users') for query in executed_queries))
        with self.client.session_transaction() as test_session:
            self.assertEqual(test_session['_flashes'][-1][1], "Reassign this user's cases before removing the account.")

    def test_admin_scam_creation_rejects_unapproved_icon(self):
        """Only a known Bootstrap icon can be stored on a public scam entry."""
        with self.client.session_transaction() as test_session:
            test_session.update({
                'user_id': 1,
                'role': 'admin',
                'csrf_token': 'test-token'
            })

        response = self.client.post('/admin/awareness-scams/add', data={
            'csrf_token': 'test-token',
            'title': 'Test scam',
            'summary': 'A test scam summary.',
            'warning_signs': 'Unexpected payment requests.',
            'safety_advice': 'Verify the request independently.',
            'icon': 'bi-invalid-icon'
        })

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, '/admin/awareness-scams')
        with self.client.session_transaction() as test_session:
            self.assertEqual(test_session['_flashes'][-1][1], 'Select a valid icon.')

    def test_ai_assistance(self):
        """Verify AI rule-based categorization and threat priority rating."""
        desc = "Someone is threatening to kill me on WhatsApp and blackmailing me."
        res = analyze_complaint(desc, "Cyber Harassment", financial_loss=0.0)
        
        # Threat to life must score CRITICAL
        self.assertEqual(res['suggested_priority'], "CRITICAL")
        self.assertEqual(res['suggested_category'], "Cyber Harassment")
        
        # Large loss must score HIGH
        desc_loss = "Lost savings through phishing link click on bank login."
        res_loss = analyze_complaint(desc_loss, "Financial Cyber Fraud", financial_loss=60000.0)
        self.assertEqual(res_loss['suggested_priority'], "HIGH")
        self.assertEqual(res_loss['suggested_category'], "Financial Cyber Fraud")

if __name__ == '__main__':
    unittest.main()
