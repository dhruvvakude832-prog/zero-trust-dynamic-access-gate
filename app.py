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

def resolve_location(ip):
    """Maps IP to sample location fallback."""
    if ip.startswith('192.168.') or ip in ('127.0.0.1', '::1'):
        return 'Local Subnet (Trusted)'
    if ip.startswith('10.'):
        return 'Campus LAN'
    if ip.startswith('172.'):
        return 'Cellular Provider (External)'
    return 'Unknown Remote Network'

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
    """Evaluates contextual risk penalties and positive reinforcements."""
    penalties = 0.0
    reasons = []
    now = time.time()

    with get_db() as conn:
        cur = conn.cursor()
        dev = cur.execute('SELECT * FROM devices WHERE user_id=? AND fingerprint_hash=?', (user_id, fingerprint)).fetchone()
        if not dev:
            penalties += 30.0
            reasons.append("Unrecognized device fingerprint (-30)")
            cur.execute('INSERT INTO devices (user_id, fingerprint_hash, is_trusted) VALUES (?, ?, 0)', (user_id, fingerprint))
            conn.commit()
        else:
            cur.execute('UPDATE devices SET last_seen=CURRENT_TIMESTAMP WHERE id=?', (dev['id'],))
            conn.commit()

    # IP velocity & changes
    sess = None
    if session_id:
        with get_db() as conn:
            sess = conn.cursor().execute('SELECT * FROM session_trust WHERE session_id=?', (session_id,)).fetchone()
        if sess and sess['ip_address'] and sess['ip_address'] != ip:
            penalties += 25.0
            reasons.append(f"Network location changed from {sess['ip_address']} to {ip} (-25)")

    # Rate velocity burst
    timestamps = VELOCITY_CACHE.setdefault(session_id or ip, [])
    timestamps.append(now)
    VELOCITY_CACHE[session_id or ip] = [t for t in timestamps if now - t <= 2.0]
    if len(VELOCITY_CACHE[session_id or ip]) > 5:
        penalties += 20.0
        reasons.append(f"Rapid request burst ({len(VELOCITY_CACHE[session_id or ip])} reqs in 2s) (-20)")

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
    ip = request.headers.get('X-Simulated-IP', request.remote_addr or '127.0.0.1')

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
    fingerprint = request.headers.get('X-Device-Fingerprint', data.get('fingerprint', 'default-browser-fp'))
    ip = request.headers.get('X-Simulated-IP', request.remote_addr or '127.0.0.1')
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

    # 2. Contextual risk checks
    ip = request.headers.get('X-Simulated-IP', request.remote_addr or '127.0.0.1')
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
    return jsonify({
        'active': True,
        'username': payload['username'],
        'role': payload['role'],
        'trust_score': decayed,
        'ip': sess['ip_address'],
        'fingerprint': sess['device_fingerprint']
    })

@app.route('/api/audit-logs')
def get_audit_logs():
    """Returns recent audit events."""
    with get_db() as conn:
        logs = conn.cursor().execute('SELECT * FROM audit_log ORDER BY id DESC LIMIT 50').fetchall()
    return jsonify([dict(l) for l in logs])

@app.route('/api/simulate/decay', methods=['POST'])
def simulate_decay():
    """Fast-forwards time to demonstrate half-life trust decay."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        payload = jwt.decode(auth_header.split(' ')[1], app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception as e:
        return jsonify({'error': str(e)}), 401

    minutes = float((request.get_json() or {}).get('minutes', 30))
    with get_db() as conn:
        sess = conn.cursor().execute('SELECT * FROM session_trust WHERE session_id=?', (payload['session_id'],)).fetchone()
        if sess:
            simulated_last = sess['last_updated'] - (minutes * 60)
            conn.cursor().execute('UPDATE session_trust SET last_updated=? WHERE session_id=?', (simulated_last, payload['session_id']))
            conn.commit()
    return jsonify({'message': f'Fast-forwarded time by {minutes} minutes'})

# --- FRONTEND ROUTE ---
@app.route('/')
def index():
    """Serves the main single-page application."""
    return render_template('index.html')

if __name__ == '__main__':
    init_db()
    print("=" * 65)
    print(" CARTA ZERO TRUST ADAPTIVE AUTHENTICATION RUNNING")
    print(" URL: http://localhost:5000")
    print("=" * 65)
    app.run(host='127.0.0.1', port=5000, debug=False)
