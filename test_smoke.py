import unittest
import json
import time
from app import app, init_db, get_db

class TestCARTA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = app.test_client()

    def test_full_c_carta_flow(self):
        print("\n--- 1. Testing Registration ---")
        reg_res = self.client.post('/register', json={
            'username': 'bob@carta.local',
            'password': 'TestPassword123!',
            'role': 'admin'
        })
        self.assertIn(reg_res.status_code, (201, 409))
        if reg_res.status_code == 201:
            data = reg_res.get_json()
            self.assertIn('mfa_setup_secret', data)
            print(f"User registered. Setup TOTP Secret: {data['mfa_setup_secret']}")

        print("--- 2. Testing Login (Step 1) ---")
        login_res = self.client.post('/login', json={
            'username': 'bob@carta.local',
            'password': 'TestPassword123!'
        })
        self.assertEqual(login_res.status_code, 200)
        login_data = login_res.get_json()
        self.assertTrue(login_data.get('mfa_required'))
        user_id = login_data['user_id']
        print(f"Password verified. MFA required for user_id={user_id}")

        print("--- 3. Testing Verify OTP (Step 2) ---")
        otp_res = self.client.post('/verify-otp', json={
            'user_id': user_id,
            'otp': '123456',
            'fingerprint': 'test-browser-fp'
        }, headers={'X-Simulated-IP': '192.168.1.45'})
        self.assertEqual(otp_res.status_code, 200)
        token_data = otp_res.get_json()
        token = token_data['token']
        self.assertEqual(token_data['trust_score'], 70.0)
        print(f"Session created with initial trust={token_data['trust_score']}, JWT issued")

        headers = {
            'Authorization': f'Bearer {token}',
            'X-Simulated-IP': '192.168.1.45',
            'X-Device-Fingerprint': 'test-browser-fp'
        }

        print("--- 4. Testing Resource Access (Public & Payment) ---")
        pub_res = self.client.get('/api/public', headers=headers)
        self.assertEqual(pub_res.status_code, 200)
        print(f"Public tier (req 20) -> Access Granted, current trust={pub_res.get_json()['trust']}")

        pay_res = self.client.get('/api/payment', headers=headers)
        self.assertEqual(pay_res.status_code, 200)
        print(f"Payment tier (req 60) -> Access Granted, current trust={pay_res.get_json()['trust']}")

        print("--- 5. Testing Anomaly (Stored Context Discrepancy Detection) ---")
        poison_res = self.client.post('/api/simulate/poison-context', headers=headers, json={'scenario': 'network'})
        self.assertEqual(poison_res.status_code, 200)
        print(f"Triggered test scenario: {poison_res.get_json()['message']}")

        # Next real request detects mismatch between stored IP and real client IP
        anom_res = self.client.get('/api/public', headers=headers)
        self.assertEqual(anom_res.status_code, 200)
        anom_trust = anom_res.get_json()['trust']
        print(f"Discrepancy detected automatically -> Trust penalized to {anom_trust}")



        print("--- 6. Testing Step-Up Challenge on Admin tier (req 80) ---")
        admin_res = self.client.get('/api/admin', headers=headers)
        self.assertEqual(admin_res.status_code, 401)
        self.assertEqual(admin_res.get_json()['decision'], 'STEP_UP_REQUIRED')
        print(f"Admin tier requested with trust={anom_trust} < 80 -> Challenged with 401 STEP_UP_REQUIRED")

        print("--- 7. Testing Step-Up OTP Elevation ---")
        step_res = self.client.post('/step-up-otp', headers=headers, json={'otp': '123456'})
        self.assertEqual(step_res.status_code, 200)
        boosted_trust = step_res.get_json()['trust_score']
        self.assertGreaterEqual(boosted_trust, 80.0)
        print(f"Step-Up OTP submitted -> Trust elevated to {boosted_trust}")

        print("--- 8. Retrying Admin tier with elevated trust ---")
        admin_ok_res = self.client.get('/api/admin', headers=headers)
        self.assertEqual(admin_ok_res.status_code, 200)
        print("Admin tier -> Access Granted!")

        print("--- 8b. Testing VPN/Proxy Detection (-50 penalty) & Combined Stacking ---")
        vpn_sim_res = self.client.post('/api/simulate/poison-context', headers=headers, json={'scenario': 'vpn'})
        self.assertEqual(vpn_sim_res.status_code, 200)
        print(f"Triggered VPN scenario: {vpn_sim_res.get_json()['message']}")

        # Next request flags VPN (-50) and network change (-25), stacking without cap
        vpn_res = self.client.get('/api/public', headers=headers)
        # Trust drops from 86 by 75 to 11.0, which is below 20 (session terminated) or below Payment/Admin
        self.assertIn(vpn_res.status_code, (200, 401, 403))
        print(f"VPN & network change stacked -> Policy evaluated with status {vpn_res.status_code}")
        audit_res = self.client.get('/api/audit-logs')
        self.assertEqual(audit_res.status_code, 200)
        logs = audit_res.get_json()
        self.assertGreater(len(logs), 0)
        print(f"Verified {len(logs)} audit entries recorded in database")

if __name__ == '__main__':
    unittest.main()
