"""
================================================================================
Intelligent Login Attempt Monitoring and Intrusion Detection System (IDS)
Automated System Verification & Unit Test Suite
================================================================================
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app import create_app
from app.models.user import User
from app.models.security import LoginAttempt, SecurityAlert
from app.services.threat_detector import ThreatDetector
from app.services.ai_risk_engine import AIRiskEngine
from app.services.otp_service import OTPService

class SystemTestSuite(unittest.TestCase):

    def setUp(self):
        """Initialize test application context and client."""
        self.app = create_app('development')
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()

    def tearDown(self):
        """Pop application context."""
        self.app_context.pop()

    def test_01_landing_page(self):
        """Verify public landing page accessibility."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Intrusion Detection', response.data)

    def test_02_user_password_hashing(self):
        """Verify bcrypt password hashing and verification methods."""
        p_hash = User.hash_password('TestSecret@123')
        user = User({'password_hash': p_hash})
        self.assertTrue(user.check_password('TestSecret@123'))
        self.assertFalse(user.check_password('WrongSecret'))

    def test_03_threat_detector_tor_check(self):
        """Verify TOR Exit Node detection rule."""
        res = ThreatDetector.analyze_attempt(
            username='test_user',
            email='test@example.com',
            ip_address='185.220.101.5', # Known TOR Node in test feed
            user_agent='Python-urllib/3.10',
            parsed_browser='Python Script',
            parsed_os='Linux',
            parsed_device='Bot'
        )
        self.assertIn('TOR_NODE', res['threats'])
        self.assertIn('AUTOMATED_BOT_UA', res['threats'])

    def test_04_ai_risk_engine_evaluation(self):
        """Verify AI Risk Engine score calculation and level mapping."""
        res = AIRiskEngine.evaluate_risk(
            user_obj=None,
            username='attacker',
            email='attacker@darknet.org',
            ip_address='185.220.101.5',
            user_agent='Python-urllib/3.10',
            parsed_browser='Python Script',
            parsed_os='Linux',
            parsed_device='Bot'
        )
        self.assertIn(res['risk_level'], ['High', 'Critical'])
        self.assertGreater(res['risk_score'], 50.0)

    def test_05_registration_and_otp_flow(self):
        """Verify registration generates OTP and verifies successfully."""
        response = self.client.post('/register', data={
            'username': 'otp_user',
            'email': 'otp_test@example.com',
            'password': 'User@123456',
            'confirm_password': 'User@123456'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        u = User.get_by_email('otp_test@example.com')
        self.assertIsNotNone(u)
        
        # Verify OTP
        otp_code = OTPService.generate_otp(u.id, otp_type='email')
        verify_res = OTPService.verify_otp(u.id, otp_code, otp_type='email')
        self.assertTrue(verify_res)

    def test_06_login_authentication(self):
        """Verify login authenticates user directly to dashboard."""
        response = self.client.post('/login', data={
            'identifier': 'john@example.com',
            'password': 'User@123456'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Welcome', response.data)

    def test_07_admin_dashboard_access_guard(self):
        """Verify unauthenticated user cannot access SOC admin routes."""
        response = self.client.get('/admin/dashboard', follow_redirects=True)
        self.assertIn(b'Login', response.data)

    def test_08_api_simulator_endpoint(self):
        """Verify live risk simulator JSON API endpoint."""
        response = self.client.post(
            '/api/simulator/evaluate',
            json={'ip': '185.220.101.5', 'user_agent': 'Python-urllib/3.10', 'failed_attempts': 3}
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('risk_score', data)
        self.assertIn('risk_level', data)

if __name__ == '__main__':
    unittest.main()
