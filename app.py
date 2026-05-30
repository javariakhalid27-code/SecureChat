import sys, os
from threat_detection import analyze_message, analyze_login, get_threat_stats, get_all_threats, analyze_request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, jsonify, session, redirect
from flask_socketio import SocketIO, emit, join_room
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import bcrypt
import base64
import random
import string

# ─── Models ───────────────────────────────────────────────

db = SQLAlchemy()

# Blacklisted usernames
BLACKLISTED_USERNAMES = [
    'admin', 'root', 'system', 'administrator', 'superuser', 'mod',
    'moderator', 'staff', 'support', 'help', 'server', 'bot',
    'null', 'undefined', 'test', 'guest', 'anonymous', 'user'
]

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    last_active = db.Column(db.DateTime, nullable=True)
    # 2FA
    twofa_secret = db.Column(db.String(10), nullable=True)
    twofa_enabled = db.Column(db.Boolean, default=False)
    twofa_pending = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {'id': self.id, 'username': self.username, 'public_key': self.public_key}

    def is_locked(self):
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        return False

    def lock_account(self):
        self.locked_until = datetime.utcnow() + timedelta(minutes=15)
        self.failed_attempts = 0

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_message = db.Column(db.Text, nullable=False)
    encrypted_key = db.Column(db.Text, nullable=False)
    sender_encrypted_key = db.Column(db.Text, nullable=True)
    iv = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

    def to_dict(self):
        return {
            'id': self.id,
            'sender': self.sender.username,
            'receiver': self.receiver.username,
            'encrypted_message': self.encrypted_message,
            'encrypted_key': self.encrypted_key,
            'iv': self.iv,
            'timestamp': self.timestamp.strftime('%H:%M'),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    username = db.Column(db.String(80), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    detail = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='success')

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username or 'Unknown',
            'action': self.action,
            'detail': self.detail,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'status': self.status
        }

# ─── Encryption ───────────────────────────────────────────

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
    public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
    return private_pem, public_pem

def aes_encrypt(message: str, key: bytes = None):
    if key is None:
        key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(message.encode()) + encryptor.finalize()
    return (base64.b64encode(encrypted).decode('utf-8'), base64.b64encode(key).decode('utf-8'), base64.b64encode(iv).decode('utf-8'))

def aes_decrypt(encrypted_b64: str, key_b64: str, iv_b64: str):
    encrypted = base64.b64decode(encrypted_b64)
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(encrypted) + decryptor.finalize()).decode('utf-8')

def rsa_encrypt_key(aes_key_b64: str, public_pem: str):
    public_key = serialization.load_pem_public_key(public_pem.encode(), backend=default_backend())
    encrypted_key = public_key.encrypt(aes_key_b64.encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return base64.b64encode(encrypted_key).decode('utf-8')

def rsa_decrypt_key(encrypted_key_b64: str, private_pem: str):
    private_key = serialization.load_pem_private_key(private_pem.encode(), password=None, backend=default_backend())
    encrypted_key = base64.b64decode(encrypted_key_b64)
    decrypted_key = private_key.decrypt(encrypted_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return decrypted_key.decode('utf-8')

# ─── App ──────────────────────────────────────────────────

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*")

with app.app_context():
    db.create_all()

# ─── Helpers ──────────────────────────────────────────────

def log_action(action, detail=None, status='success', user_id=None, username=None):
    try:
        log = AuditLog(
            user_id=user_id or session.get('user_id'),
            username=username or session.get('username'),
            action=action, detail=detail,
            ip_address=request.remote_addr, status=status
        )
        db.session.add(log)
        db.session.commit()
    except:
        pass

def check_password_strength(password):
    score = 0
    issues = []
    if len(password) >= 8: score += 1
    else: issues.append("At least 8 characters required")
    if any(c.isupper() for c in password): score += 1
    else: issues.append("At least one uppercase letter required")
    if any(c.islower() for c in password): score += 1
    else: issues.append("At least one lowercase letter required")
    if any(c.isdigit() for c in password): score += 1
    else: issues.append("At least one number required")
    if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password): score += 1
    else: issues.append("Special character recommended (!@#$%)")
    return score, issues

def generate_2fa_code():
    return ''.join(random.choices(string.digits, k=6))

def update_last_active():
    if 'user_id' in session:
        try:
            user = User.query.get(session['user_id'])
            if user:
                user.last_active = datetime.utcnow()
                db.session.commit()
        except:
            pass

def check_session_timeout():
    if 'user_id' in session and 'last_active' in session:
        last = datetime.fromisoformat(session['last_active'])
        if datetime.utcnow() - last > timedelta(minutes=30):
            log_action('SESSION_TIMEOUT', 'Auto logout after 30 min inactivity', 'warning')
            session.clear()
            return True
    return False

# ─── Routes ───────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/login')
def login_page():
    return render_template('index.html')

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('chat.html')

@app.route('/landing')
def landing():
    return render_template('landing.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/how-it-works')
def how_it_works():
    return render_template('how_it_works.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/security-log')
def security_log():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('security_log.html')
@app.route('/threat-detection')
def threat_detection_page():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('threat_dashboard.html')

@app.route('/firewall')
def firewall():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('firewall.html')

@app.route('/api/threats')
def get_threats():
    if 'user_id' not in session:
        return jsonify({'success': False})
    stats = get_threat_stats()
    threats = get_all_threats()
    return jsonify({'success': True, 'threats': threats, 'stats': stats})

@app.route('/api/simulate-threat', methods=['POST'])
def simulate_threat():
    if 'user_id' not in session:
        return jsonify({'success': False})
    data = request.json
    result = analyze_message(
        data.get('username', 'TestUser'),
        data.get('username', 'TestUser'),
        data.get('message', ''),
        request.remote_addr
    )
    return jsonify({'success': True, 'result': result})

# ─── API ──────────────────────────────────────────────────

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required!'})

    if len(username) < 3:
        return jsonify({'success': False, 'message': 'Username must be at least 3 characters!'})

    if len(username) > 20:
        return jsonify({'success': False, 'message': 'Username must be under 20 characters!'})

    if not username.replace('_','').replace('-','').isalnum():
        return jsonify({'success': False, 'message': 'Username can only contain letters, numbers, _ and -'})

    if username.lower() in BLACKLISTED_USERNAMES:
        log_action('REGISTER_BLOCKED', f'Blacklisted username attempted: {username}', 'danger', username=username)
        return jsonify({'success': False, 'message': f'Username "{username}" is reserved and cannot be used!'})

    score, issues = check_password_strength(password)
    if score < 3:
        return jsonify({'success': False, 'message': 'Weak password: ' + ', '.join(issues[:2])})

    if User.query.filter_by(username=username).first():
        log_action('REGISTER_FAILED', f'Username already exists: {username}', 'warning', username=username)
        return jsonify({'success': False, 'message': 'Username already exists!'})

    private_key, public_key = generate_rsa_keys()
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    user = User(username=username, password_hash=password_hash, public_key=public_key, private_key=private_key)
    db.session.add(user)
    db.session.commit()

    session['user_id'] = user.id
    session['username'] = user.username
    session['last_active'] = datetime.utcnow().isoformat()
    session.permanent = True

    log_action('REGISTER_SUCCESS', f'New account — RSA-2048 keys generated — bcrypt hashed', 'success', user_id=user.id, username=username)
    return jsonify({'success': True, 'message': 'Account created!', 'username': username})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    twofa_code = data.get('twofa_code', '').strip()

    user = User.query.filter_by(username=username).first()

    if not user:
        log_action('LOGIN_FAILED', f'Unknown username: {username}', 'danger', username=username)
        return jsonify({'success': False, 'message': 'Invalid username or password!'})

    if user.is_locked():
        remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60) + 1
        log_action('LOGIN_BLOCKED', f'Account locked — {remaining} mins remaining', 'danger', user_id=user.id, username=username)
        return jsonify({'success': False, 'message': f'Account locked! Try again in {remaining} minutes.', 'locked': True})

    if not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        user.failed_attempts += 1
        if user.failed_attempts >= 3:
            user.lock_account()
            db.session.commit()
            log_action('ACCOUNT_LOCKED', 'Locked after 3 failed attempts', 'danger', user_id=user.id, username=username)
            return jsonify({'success': False, 'message': 'Account locked for 15 minutes after 3 failed attempts!', 'locked': True})
        db.session.commit()
        remaining = 3 - user.failed_attempts
        log_action('LOGIN_FAILED', f'Wrong password — {user.failed_attempts}/3 attempts', 'warning', user_id=user.id, username=username)
        return jsonify({'success': False, 'message': f'Wrong password! {remaining} attempts left before lockout.'})

    # 2FA check
    if user.twofa_enabled:
        if not twofa_code:
            new_code = generate_2fa_code()
            user.twofa_secret = new_code
            user.twofa_pending = True
            db.session.commit()
            log_action('2FA_REQUIRED', f'2FA code generated for {username}', 'success', user_id=user.id, username=username)
            return jsonify({'success': False, 'require_2fa': True, 'message': f'2FA Required! Your code is: {new_code}', '2fa_code': new_code})
        if twofa_code != user.twofa_secret:
            log_action('2FA_FAILED', f'Wrong 2FA code for {username}', 'danger', user_id=user.id, username=username)
            return jsonify({'success': False, 'message': 'Invalid 2FA code!'})
        user.twofa_pending = False

    user.failed_attempts = 0
    user.locked_until = None
    user.last_login = datetime.utcnow()
    user.last_active = datetime.utcnow()
    db.session.commit()

    session['user_id'] = user.id
    session['username'] = user.username
    session['last_active'] = datetime.utcnow().isoformat()
    session.permanent = True

    log_action('LOGIN_SUCCESS', f'Authenticated via bcrypt — session started — IP: {request.remote_addr}', 'success', user_id=user.id, username=username)
    return jsonify({'success': True, 'username': username})

@app.route('/api/logout', methods=['POST'])
def logout():
    log_action('LOGOUT', 'Session terminated by user')
    session.clear()
    return jsonify({'success': True})

@app.route('/api/users')
def get_users():
    if 'user_id' not in session:
        return jsonify({'success': False})
    update_last_active()
    session['last_active'] = datetime.utcnow().isoformat()
    users = User.query.filter(User.id != session['user_id']).all()
    return jsonify({'success': True, 'users': [u.to_dict() for u in users]})

@app.route('/api/messages/<int:other_user_id>')
def get_messages(other_user_id):
    if 'user_id' not in session:
        return jsonify({'success': False})
    update_last_active()
    session['last_active'] = datetime.utcnow().isoformat()
    current_user = User.query.get(session['user_id'])

    # Delete expired messages
    expired = Message.query.filter(
        Message.expires_at != None,
        Message.expires_at < datetime.utcnow()
    ).all()
    for msg in expired:
        db.session.delete(msg)
    if expired:
        db.session.commit()

    messages = Message.query.filter(
        ((Message.sender_id == session['user_id']) & (Message.receiver_id == other_user_id)) |
        ((Message.sender_id == other_user_id) & (Message.receiver_id == session['user_id']))
    ).order_by(Message.timestamp).all()

    result = []
    for msg in messages:
        try:
            if msg.receiver_id == session['user_id']:
                aes_key = rsa_decrypt_key(msg.encrypted_key, current_user.private_key)
            else:
                aes_key = rsa_decrypt_key(msg.sender_encrypted_key, current_user.private_key)
            decrypted = aes_decrypt(msg.encrypted_message, aes_key, msg.iv)
        except Exception as e:
            decrypted = "✓ Sent"
        result.append({**msg.to_dict(), 'decrypted_message': decrypted, 'is_mine': msg.sender_id == session['user_id']})
    return jsonify({'success': True, 'messages': result})

@app.route('/api/send', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return jsonify({'success': False})
    update_last_active()
    session['last_active'] = datetime.utcnow().isoformat()

   


    data = request.json
    receiver_id = data.get('receiver_id')
    message_text = data.get('message', '').strip()
    expiry_minutes = data.get('expiry_minutes', None)

    if not message_text:
        return jsonify({'success': False, 'message': 'Message is empty!'})
    # AI Threat Analysis
    threat_result = analyze_message(session['user_id'], session['username'], message_text, request.remote_addr)
    if threat_result['blocked']:
        return jsonify({'success': False, 'message': 'Message blocked by AI security system!'})

    receiver = User.query.get(receiver_id)
    if not receiver:
        return jsonify({'success': False, 'message': 'User not found!'})

    current_user = User.query.get(session['user_id'])
    encrypted_msg, aes_key_b64, iv_b64 = aes_encrypt(message_text)
    encrypted_key = rsa_encrypt_key(aes_key_b64, receiver.public_key)
    sender_encrypted_key = rsa_encrypt_key(aes_key_b64, current_user.public_key)

    expires_at = None
    if expiry_minutes:
        expires_at = datetime.utcnow() + timedelta(minutes=int(expiry_minutes))

    msg = Message(
        sender_id=session['user_id'], receiver_id=receiver_id,
        encrypted_message=encrypted_msg, encrypted_key=encrypted_key,
        sender_encrypted_key=sender_encrypted_key, iv=iv_b64,
        expires_at=expires_at
    )
    db.session.add(msg)
    db.session.commit()

    expiry_info = f' — expires in {expiry_minutes}min' if expiry_minutes else ''
    log_action('MESSAGE_ENCRYPTED', f'AES-256 → RSA-2048 wrapped → sent to {receiver.username}{expiry_info}', 'success')


    sender = User.query.get(session['user_id'])
    socketio.emit('new_message', {
        'sender': sender.username, 'sender_id': session['user_id'],
        'receiver_id': receiver_id, 'encrypted_message': encrypted_msg,
        'decrypted_message': message_text, 'timestamp': msg.timestamp.strftime('%H:%M'),
        'msg_id': msg.id, 'expires_at': expires_at.isoformat() if expires_at else None
    }, room=f'user_{receiver_id}')



    return jsonify({'success': True, 'encrypted_message': encrypted_msg, 'aes_key': aes_key_b64, 'iv': iv_b64, 'msg_id': msg.id})


@app.route('/api/me')
def get_me():
    if 'user_id' not in session:
        return jsonify({'success': False})
    update_last_active()
    session['last_active'] = datetime.utcnow().isoformat()
    user = User.query.get(session['user_id'])
    return jsonify({'success': True, 'user_id': user.id, 'username': user.username, 'public_key': user.public_key, 'twofa_enabled': user.twofa_enabled})

@app.route('/api/enable-2fa', methods=['POST'])
def enable_2fa():
    if 'user_id' not in session:
        return jsonify({'success': False})
    user = User.query.get(session['user_id'])
    user.twofa_enabled = not user.twofa_enabled
    db.session.commit()
    status = 'enabled' if user.twofa_enabled else 'disabled'
    log_action('2FA_TOGGLE', f'Two-Factor Authentication {status}', 'success')
    return jsonify({'success': True, 'enabled': user.twofa_enabled, 'message': f'2FA {status} successfully!'})

@app.route('/api/audit-logs')
def get_audit_logs():
    if 'user_id' not in session:
        return jsonify({'success': False})
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return jsonify({'success': True, 'logs': [l.to_dict() for l in logs]})

@app.route('/api/security-stats')
def get_security_stats():
    if 'user_id' not in session:
        return jsonify({'success': False})
    total_msgs = Message.query.count()
    total_users = User.query.count()
    total_logs = AuditLog.query.count()
    failed_logins = AuditLog.query.filter_by(status='danger').count()
    locked_accounts = User.query.filter(User.locked_until > datetime.utcnow()).count()
    return jsonify({
        'success': True, 'total_messages': total_msgs, 'total_users': total_users,
        'total_logs': total_logs, 'failed_logins': failed_logins, 'locked_accounts': locked_accounts
    })

@app.route('/api/password-strength', methods=['POST'])
def password_strength():
    data = request.json
    password = data.get('password', '')
    score, issues = check_password_strength(password)
    return jsonify({'score': score, 'issues': issues, 'strength': ['Very Weak','Weak','Fair','Good','Strong'][min(score,4)]})

@app.route('/api/session-check')
def session_check():
    if 'user_id' not in session:
        return jsonify({'valid': False})
    if 'last_active' in session:
        last = datetime.fromisoformat(session['last_active'])
        idle_minutes = (datetime.utcnow() - last).total_seconds() / 60
        if idle_minutes > 30:
            log_action('SESSION_TIMEOUT', f'Auto logout after {int(idle_minutes)} min inactivity', 'warning')
            session.clear()
            return jsonify({'valid': False, 'reason': 'timeout'})
        remaining = int(30 - idle_minutes)
        return jsonify({'valid': True, 'idle_minutes': int(idle_minutes), 'remaining_minutes': remaining})
    return jsonify({'valid': True})

# ─── SocketIO ─────────────────────────────────────────────

@socketio.on('join')
def on_join(data):
    user_id = data.get('user_id')
    join_room(f'user_{user_id}')
    join_room('broadcast')
    socketio.emit('user_online', {'user_id': user_id}, room='broadcast')

@socketio.on('join_firewall')
def join_firewall():
    join_room('broadcast')


@socketio.on('typing')
def on_typing(data):
    socketio.emit('typing', {'from': data.get('from'), 'username': data.get('username')}, room=f"user_{data.get('to')}")

@socketio.on('stop_typing')
def on_stop_typing(data):
    socketio.emit('stop_typing', {'from': data.get('from')}, room=f"user_{data.get('to')}")

@socketio.on('disconnect')
def on_disconnect():
    pass

@app.after_request
def firewall_check(response):
    try:
        ip = request.remote_addr
        path = request.path
        method = request.method
        if not path.startswith('/static'):
            socketio.emit('real_request', {
                'ip': ip,
                'path': path,
                'method': method,
                'time': datetime.utcnow().strftime('%H:%M:%S'),
                'status': response.status_code
            }, namespace='/')
    except:
        pass
    return response

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)