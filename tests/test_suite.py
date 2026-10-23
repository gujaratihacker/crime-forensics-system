import os
import sys
import unittest
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
        
    def test_password_hashing(self):
        """Test secure password hashing and verification."""
        password = "SecurePassword@123"
        hash_val = generate_password_hash(password)
        
        # Verify hash is not plaintext
        self.assertNotEqual(password, hash_val)
        
        # Verify check works
        self.assertTrue(check_password_hash(hash_val, password))
        self.assertFalse(check_password_hash(hash_val, "WrongPassword@123"))

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
