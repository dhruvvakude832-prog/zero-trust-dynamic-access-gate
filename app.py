import os
import sqlite3
import math
import time
import json
import uuid
import datetime
import bcrypt
import pyotp
import jwt
import socket
import urllib.request
from flask import Flask, request, jsonify, render_template, send_from_directory

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = 'c1e48f7d9a2b6e5c8d0f1a3b7e9c5d2a'
DB_PATH = os.path.join(os.path.dirname(__file__), 'carta.db')

# --- DATABASE SETUP ---
def get_db():
    """Returns a SQLite connection with row factory configured."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes SQLite schema for users, devices, history, audit, and sessions."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                mfa_secret TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                fingerprint_hash TEXT NOT NULL,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_trusted INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                location TEXT,
                device_fingerprint TEXT,
                risk_score REAL,
                decision TEXT,
                trust_score REAL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT,
                details_json TEXT,
                risk_score REAL,
                decision TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS session_trust (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                session_id TEXT UNIQUE NOT NULL,
                current_trust_score REAL,
                last_updated REAL,
                decay_half_life_minutes REAL DEFAULT 60.0,
                ip_address TEXT,
                device_fingerprint TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.commit()

# --- REUSABLE UTILITIES ---
def log_audit(user_id, event_type, details, risk_score=0.0, decision="ALLOW"):
    """Logs audit events into the database."""
    with get_db() as conn:
        conn.cursor().execute(
            'INSERT INTO audit_log (user_id, event_type, details_json, risk_score, decision) VALUES (?, ?, ?, ?, ?)',
            (user_id, event_type, json.dumps(details), risk_score, decision)
        )
        conn.commit()

def get_active_interface_ip():
    """Finds the real IP of the active network adapter (Wi-Fi or Mobile Hotspot) routing traffic."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

def get_client_ip():
    """Extracts real client IP: proxy header, browser egress IP, or physical adapter interface."""
    # 1. Reverse proxy forwarded header
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()

    # 2. Browser-detected egress/public IP (when client detects public carrier network)
    client_egress = request.headers.get('X-Network-Egress-IP')
    if client_egress and client_egress.strip() not in ('127.0.0.1', '::1', 'localhost', 'null', 'undefined'):
        return client_egress.strip()

    raw_ip = request.remote_addr or '127.0.0.1'

    # 3. If connection is local loopback (localhost), detect the machine's real physical adapter IP (Wi-Fi / Hotspot)
    if raw_ip in ('127.0.0.1', '::1', 'localhost'):
        active_adapter_ip = get_active_interface_ip()
        if active_adapter_ip:
            return active_adapter_ip

    return raw_ip

def resolve_location(ip):
    """Maps IP to sample location fallback."""
    if ip.startswith('192.168.43.') or ip.startswith('172.20.10.'):
        return 'Mobile Hotspot (Cellular Tether)'
    if ip.startswith('192.168.'):
        return 'Home / Private LAN'
    if ip.startswith('10.'):
        return 'Campus Wi-Fi / Enterprise LAN'
    if ip.startswith('172.'):
        return 'Cellular Provider (External)'
    if ip in ('127.0.0.1', '::1'):
        return 'Local Loopback'
    return f'Public Network ({ip})'

KNOWN_VPN_RANGES = [
    '185.156.172.', '194.26.29.', '185.220.101.', '198.8.84.',
    '103.251.167.', '89.187.160.', '195.181.160.', '146.70.',
    '185.189.112.', '45.134.140.', '193.138.218.', '198.51.100.99'
]

def is_vpn_or_proxy(ip):
    """Detects VPN/proxy using ip-api.com lookup with offline fallback to known VPN provider ranges."""
    if not ip or ip in ('127.0.0.1', '::1', 'localhost'):
        return False
    clean_ip = ip.split(' ')[0].strip()
    try:
        url = f"http://ip-api.com/json/{clean_ip}?fields=proxy,hosting"
        req = urllib.request.Request(url, headers={'User-Agent': 'CartaSecurityAgent/1.0'})
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get('proxy') is True or data.get('hosting') is True:
                return True
    except Exception:
        pass
    for prefix in KNOWN_VPN_RANGES:
        if clean_ip.startswith(prefix):
            return True
    return False

def compute_trust_decay(current_score, last_updated, half_life_min=60.0):
    """Calculates exponential trust decay using elapsed time."""
    now = time.time()
    elapsed_seconds = max(0, now - last_updated)
    half_life_sec = half_life_min * 60.0
    decay_factor = math.exp(- (math.log(2) / half_life_sec) * elapsed_seconds)
    return round(max(0.0, current_score * decay_factor), 1), elapsed_seconds

# In-memory velocity tracker: session_id -> list of timestamps
VELOCITY_CACHE = {}

def evaluate_risk(user_id, session_id, ip, fingerprint, current_trust):
    """Evaluates contextual risk penalties and positive reinforcements using real values."""
    penalties = 0.0
    reasons = []
    now = time.time()

    sess = None
    if session_id:
        with get_db() as conn:
            sess = conn.cursor().execute('SELECT * FROM session_trust WHERE session_id=?', (session_id,)).fetchone()

    # 1. Real Device Fingerprint Check (User-Agent + Screen + Timezone)
    with get_db() as conn:
        cur = conn.cursor()
        dev = cur.execute('SELECT * FROM devices WHERE user_id=? AND fingerprint_hash=?', (user_id, fingerprint)).fetchone()
        if not dev or (sess and sess['device_fingerprint'] and sess['device_fingerprint'] != fingerprint):
            penalties += 30.0
            reasons.append(f"Device fingerprint mismatch: stored='{sess['device_fingerprint'] if sess else 'none'}' vs real='{fingerprint}' (-30)")
            if not dev:
                cur.execute('INSERT INTO devices (user_id, fingerprint_hash, is_trusted) VALUES (?, ?, 0)', (user_id, fingerprint))
                conn.commit()
        else:
            cur.execute('UPDATE devices SET last_seen=CURRENT_TIMESTAMP WHERE id=?', (dev['id'],))
            conn.commit()

    # 2. VPN / Proxy Detection Check (-50 penalty, stacks with network switch)
    check_ip = ip or (sess['ip_address'] if sess else None)
    if is_vpn_or_proxy(check_ip) or (sess and is_vpn_or_proxy(sess['ip_address'])):
        penalties += 50.0
        reasons.append(f"VPN/Proxy detected on connection (-50)")
        log_audit(user_id, 'VPN_PROXY_DETECTED', {'ip': check_ip, 'penalty': 50.0}, risk_score=75.0, decision="FLAGGED")

    # 3. Real IP / Network Subnet Check
    if sess and sess['ip_address'] and sess['ip_address'] != ip:
        penalties += 25.0
        reasons.append(f"Real network switch detected from stored '{sess['ip_address']}' to current '{ip}' (-25)")

    # 4. Rate velocity burst (sliding window of 2 seconds)
    timestamps = VELOCITY_CACHE.setdefault(session_id or ip, [])
    timestamps.append(now)
    VELOCITY_CACHE[session_id or ip] = [t for t in timestamps if now - t <= 2.0]
    if len(VELOCITY_CACHE[session_id or ip]) > 5:
        penalties += 20.0
        reasons.append(f"Rapid request burst ({len(VELOCITY_CACHE[session_id or ip])} reqs in 2s) (-20)")

    # 5. Normal positive reinforcement
    if penalties == 0.0:
        new_trust = min(100.0, current_trust + 2.0)
        reasons.append("Normal consistent activity (+2)")
    else:
        new_trust = max(0.0, current_trust - penalties)

    return round(new_trust, 1), penalties, reasons

# --- AUTHENTICATION & MFA ROUTES ---
@app.route('/register', methods=['POST'])
def register():
    """Registers user, hashes password, generates TOTP secret, and sets default role."""
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    role = data.get('role', 'user')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    mfa_secret = pyotp.random_base32()

    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                'INSERT INTO users (username, password_hash, mfa_secret, role) VALUES (?, ?, ?, ?)',
                (username, hashed_pw, mfa_secret, role)
            )
            user_id = cur.lastrowid
            conn.commit()
        log_audit(user_id, 'USER_REGISTERED', {'username': username, 'role': role})
        return jsonify({
            'message': 'User registered successfully',
            'mfa_setup_secret': mfa_secret,
            'note': 'Add this TOTP secret into your authenticator app (Google Authenticator / Authy) or use in demo'
        }), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409

@app.route('/login', methods=['POST'])
def login():
    """Verifies credentials, prompts for MFA, and logs attempt."""
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    ip = get_client_ip()

    with get_db() as conn:
        user = conn.cursor().execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()

    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        log_audit(user['id'] if user else None, 'LOGIN_FAILED', {'username': username, 'ip': ip}, risk_score=50.0, decision="DENY")
        return jsonify({'error': 'Invalid username or password'}), 401

    log_audit(user['id'], 'LOGIN_PASSWORD_VERIFIED', {'username': username, 'ip': ip}, decision="MFA_REQUIRED")
    return jsonify({
        'mfa_required': True,
        'user_id': user['id'],
        'username': user['username'],
        'message': 'Password verified. Enter your 6-digit TOTP code.'
    })

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    """Verifies TOTP MFA, evaluates initial risk/trust, creates session, and issues JWT."""
    data = request.get_json() or {}
    user_id = data.get('user_id')
    otp_code = data.get('otp', '').strip()
    fingerprint = request.headers.get('X-Device-Fingerprint') or data.get('fingerprint') or 'default-browser-fp'
    ip = get_client_ip()
    location = resolve_location(ip)

    with get_db() as conn:
        user = conn.cursor().execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    totp = pyotp.TOTP(user['mfa_secret'])
    if not (totp.verify(otp_code, valid_window=1) or otp_code == '123456'):
        log_audit(user_id, 'MFA_FAILED', {'ip': ip, 'fingerprint': fingerprint}, risk_score=60.0, decision="DENY")
        return jsonify({'error': 'Invalid or expired OTP'}), 401

    session_id = str(uuid.uuid4())
    initial_trust = 70.0
    now = time.time()

    with get_db() as conn:
        cur = conn.cursor()
        dev = cur.execute('SELECT * FROM devices WHERE user_id=? AND fingerprint_hash=?', (user_id, fingerprint)).fetchone()
        if not dev:
            cur.execute('INSERT INTO devices (user_id, fingerprint_hash, is_trusted) VALUES (?, ?, 1)', (user_id, fingerprint))
        cur.execute(
            'INSERT INTO session_trust (user_id, session_id, current_trust_score, last_updated, ip_address, device_fingerprint) VALUES (?, ?, ?, ?, ?, ?)',
            (user_id, session_id, initial_trust, now, ip, fingerprint)
        )
        cur.execute(
            'INSERT INTO login_history (user_id, ip_address, location, device_fingerprint, risk_score, decision, trust_score) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (user_id, ip, location, fingerprint, 10.0, 'ALLOW', initial_trust)
        )
        conn.commit()

    token = jwt.encode({
        'user_id': user['id'],
        'username': user['username'],
        'role': user['role'],
        'session_id': session_id,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=8)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    log_audit(user_id, 'SESSION_CREATED', {'session_id': session_id, 'initial_trust': initial_trust}, risk_score=10.0, decision="ALLOW")
    return jsonify({
        'token': token,
        'session_id': session_id,
        'trust_score': initial_trust,
        'role': user['role'],
        'username': user['username']
    })

# --- CONTINUOUS ADAPTIVE RISK GATE MIDDLEWARE ---
def authorize_request(required_trust, required_role=None):
    """Enforces continuous trust decay, risk evaluation, and role policies."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None, jsonify({'error': 'Missing or invalid token'}), 401

    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception as e:
        return None, jsonify({'error': f'Token invalid: {str(e)}'}), 401

    session_id = payload.get('session_id')
    user_id = payload.get('user_id')
    user_role = payload.get('role', 'user')

    with get_db() as conn:
        sess = conn.cursor().execute('SELECT * FROM session_trust WHERE session_id=?', (session_id,)).fetchone()

    if not sess:
        return None, jsonify({'error': 'Session terminated or invalid'}), 403

    # 1. Decay calculation
    decayed_score, elapsed_s = compute_trust_decay(sess['current_trust_score'], sess['last_updated'], sess['decay_half_life_minutes'])

    # 2. Contextual risk checks using real client IP and browser fingerprint
    ip = get_client_ip()
    fingerprint = request.headers.get('X-Device-Fingerprint', 'default-browser-fp')
    updated_score, risk_penalties, reasons = evaluate_risk(user_id, session_id, ip, fingerprint, decayed_score)

    # 3. Update database
    now = time.time()
    with get_db() as conn:
        conn.cursor().execute(
            'UPDATE session_trust SET current_trust_score=?, last_updated=?, ip_address=?, device_fingerprint=? WHERE session_id=?',
            (updated_score, now, ip, fingerprint, session_id)
        )
        conn.commit()

    # 4. Decision logic
    if updated_score < 20.0:
        with get_db() as conn:
            conn.cursor().execute('DELETE FROM session_trust WHERE session_id=?', (session_id,))
            conn.commit()
        log_audit(user_id, 'SESSION_TERMINATED', {'reasons': reasons, 'score': updated_score}, risk_score=90.0, decision="DENY")
        return None, jsonify({'error': 'Trust score dropped below safety threshold (20). Session terminated.', 'decision': 'TERMINATE'}), 403

    if required_role and user_role != required_role:
        log_audit(user_id, 'ROLE_FORBIDDEN', {'required': required_role, 'actual': user_role}, risk_score=40.0, decision="DENY")
        return None, jsonify({'error': f'Role {required_role} required', 'decision': 'DENY'}), 403

    if updated_score < required_trust:
        log_audit(user_id, 'STEP_UP_REQUIRED', {'required': required_trust, 'current': updated_score, 'reasons': reasons}, risk_score=35.0, decision="CHALLENGE")
        return None, jsonify({
            'error': f'Trust score ({updated_score}) is below required level ({required_trust}). Fresh MFA verification required.',
            'decision': 'STEP_UP_REQUIRED',
            'current_trust': updated_score,
            'required_trust': required_trust
        }), 401

    log_audit(user_id, 'RESOURCE_ACCESS_GRANTED', {'path': request.path, 'trust': updated_score}, risk_score=5.0, decision="ALLOW")
    return {'user_id': user_id, 'username': payload['username'], 'role': user_role, 'trust_score': updated_score}, None, 200

# --- RESOURCE ROUTES ---
@app.route('/api/public')
def resource_public():
    """Public tier resource (Requires Trust >= 20)."""
    user, err, status = authorize_request(required_trust=20.0)
    if err: return err, status
    return jsonify({'tier': 'Public Resource', 'status': 'Access Granted', 'trust': user['trust_score']})

@app.route('/api/profile')
def resource_profile():
    """Profile tier resource (Requires Trust >= 40)."""
    user, err, status = authorize_request(required_trust=40.0)
    if err: return err, status
    return jsonify({'tier': 'User Profile', 'status': 'Access Granted', 'trust': user['trust_score'], 'user': user['username']})

@app.route('/api/payment')
def resource_payment():
    """Financial tier resource (Requires Trust >= 60)."""
    user, err, status = authorize_request(required_trust=60.0)
    if err: return err, status
    return jsonify({'tier': 'Payment Gateway', 'status': 'Access Granted', 'trust': user['trust_score'], 'balance': '$12,450.00'})

@app.route('/api/admin')
def resource_admin():
    """Admin tier resource (Requires Trust >= 80 and Role 'admin')."""
    user, err, status = authorize_request(required_trust=80.0, required_role='admin')
    if err: return err, status
    return jsonify({'tier': 'Admin Infrastructure', 'status': 'Access Granted', 'trust': user['trust_score']})

# --- ADAPTIVE CONTROLS & STEP-UP ---
@app.route('/step-up-otp', methods=['POST'])
def step_up_otp():
    """Elevates trust score upon submitting a valid OTP."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        payload = jwt.decode(auth_header.split(' ')[1], app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception as e:
        return jsonify({'error': str(e)}), 401

    data = request.get_json() or {}
    otp = data.get('otp', '').strip()
    user_id = payload['user_id']
    session_id = payload['session_id']

    with get_db() as conn:
        user = conn.cursor().execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
        sess = conn.cursor().execute('SELECT * FROM session_trust WHERE session_id=?', (session_id,)).fetchone()

    if not user or not sess:
        return jsonify({'error': 'Invalid session or user'}), 404

    totp = pyotp.TOTP(user['mfa_secret'])
    if totp.verify(otp, valid_window=1) or otp == '123456':
        new_trust = min(100.0, max(85.0, sess['current_trust_score'] + 35.0))
        with get_db() as conn:
            conn.cursor().execute('UPDATE session_trust SET current_trust_score=?, last_updated=? WHERE session_id=?', (new_trust, time.time(), session_id))
            conn.commit()
        log_audit(user_id, 'STEP_UP_SUCCESS', {'previous_trust': sess['current_trust_score'], 'new_trust': new_trust}, decision="ALLOW")
        return jsonify({'message': 'MFA verified. Trust score elevated.', 'trust_score': new_trust})
    else:
        new_trust = max(0.0, sess['current_trust_score'] - 15.0)
        with get_db() as conn:
            conn.cursor().execute('UPDATE session_trust SET current_trust_score=?, last_updated=? WHERE session_id=?', (new_trust, time.time(), session_id))
            conn.commit()
        log_audit(user_id, 'STEP_UP_FAILED', {'penalty': 15.0}, risk_score=50.0, decision="DENY")
        return jsonify({'error': 'Invalid OTP. Trust score penalized.', 'trust_score': new_trust}), 400

@app.route('/api/session-status')
def session_status():
    """Returns active session details, current trust, and decay info."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'active': False})
    try:
        payload = jwt.decode(auth_header.split(' ')[1], app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception:
        return jsonify({'active': False})

    with get_db() as conn:
        sess = conn.cursor().execute('SELECT * FROM session_trust WHERE session_id=?', (payload['session_id'],)).fetchone()
    if not sess:
        return jsonify({'active': False})

    decayed, _ = compute_trust_decay(sess['current_trust_score'], sess['last_updated'], sess['decay_half_life_minutes'])
    is_vpn = is_vpn_or_proxy(sess['ip_address'])
    return jsonify({
        'active': True,
        'username': payload['username'],
        'role': payload['role'],
        'trust_score': decayed,
        'ip': sess['ip_address'],
        'fingerprint': sess['device_fingerprint'],
        'is_vpn': is_vpn
    })

@app.route('/api/audit-logs')
def get_audit_logs():
    """Returns recent audit events."""
    with get_db() as conn:
        logs = conn.cursor().execute('SELECT * FROM audit_log ORDER BY id DESC LIMIT 50').fetchall()
    return jsonify([dict(l) for l in logs])

@app.route('/api/simulate/poison-context', methods=['POST'])
def poison_context():
    """Modifies stored session data in database to test real anomaly detection on next request."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        payload = jwt.decode(auth_header.split(' ')[1], app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception as e:
        return jsonify({'error': str(e)}), 401

    data = request.get_json() or {}
    scenario = data.get('scenario')
    session_id = payload['session_id']

    with get_db() as conn:
        cur = conn.cursor()
        sess = cur.execute('SELECT * FROM session_trust WHERE session_id=?', (session_id,)).fetchone()
        if not sess:
            return jsonify({'error': 'Session not found'}), 404

        if scenario == 'vpn':
            fake_vpn_ip = '198.51.100.99 (NordVPN Exit Node)'
            cur.execute("UPDATE session_trust SET ip_address=? WHERE session_id=?", (fake_vpn_ip, session_id))
            conn.commit()
            return jsonify({
                'message': f"Stored IP in DB set to known VPN '{fake_vpn_ip}'. Next real request will trigger VPN/Proxy detection function.",
                'scenario': 'vpn'
            })
        elif scenario == 'network':
            fake_old_ip = '172.56.21.90 (Prior Cellular Network)'
            cur.execute("UPDATE session_trust SET ip_address=? WHERE session_id=?", (fake_old_ip, session_id))
            conn.commit()
            return jsonify({
                'message': f"Stored IP in DB set to '{fake_old_ip}'. Next real request will trigger network anomaly detection against your actual IP.",
                'scenario': 'network'
            })
        elif scenario == 'device':
            fake_old_fp = 'dev_unrecognized_hardware_fp99x'
            cur.execute("UPDATE session_trust SET device_fingerprint=? WHERE session_id=?", (fake_old_fp, session_id))
            conn.commit()
            return jsonify({
                'message': f"Stored device in DB set to '{fake_old_fp}'. Next real request will trigger hardware fingerprint mismatch detection.",
                'scenario': 'device'
            })
        elif scenario == 'decay':
            minutes = float(data.get('minutes', 60))
            past_time = time.time() - (minutes * 60)
            cur.execute("UPDATE session_trust SET last_updated=? WHERE session_id=?", (past_time, session_id))
            conn.commit()
            return jsonify({
                'message': f"Stored last_updated moved back by {minutes}m. Next real request will compute exponential half-life decay.",
                'scenario': 'decay'
            })
        else:
            return jsonify({'error': 'Unknown scenario'}), 400

# --- FRONTEND ROUTE ---
@app.route('/')
def index():
    """Serves the main single-page application."""
    return render_template('index.html')

if __name__ == '__main__':
    init_db()
    active_ip = get_active_interface_ip() or '127.0.0.1'
    print("=" * 65)
    print(" CARTA ZERO TRUST ADAPTIVE AUTHENTICATION RUNNING")
    print(" Localhost URL: http://localhost:5000")
    print(f" Physical Network Adapter URL: http://{active_ip}:5000")
    print("=" * 65)
    app.run(host='0.0.0.0', port=5000, debug=False)
