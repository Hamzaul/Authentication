import re
import os
import bcrypt
import secrets
from datetime import datetime, timedelta
 
from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
from flask_mail import Mail, Message
from pymongo import MongoClient
from bson import ObjectId
from dotenv import load_dotenv
 
# ====== Load env ======
load_dotenv()
 
app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app, supports_credentials=True, origins="*")
app.secret_key = os.getenv("SECRET_KEY", "devsecret")
 
# ====== Session Cookie Config (for cross-origin admin sessions) ======
app.config.update(
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=True,
)
 
# ====== Config ======
MONGO_URI    = os.getenv('MONGO_URI')
ADMIN_USER   = os.getenv("ADMIN_USER")
ADMIN_PASS   = os.getenv("ADMIN_PASS")
BASE_URL     = os.getenv("BASE_URL", "https://authentication-eng2.onrender.com").rstrip("/")
 
# ====== Mail Setup ======
app.config.update(
    MAIL_SERVER          = os.getenv("MAIL_SERVER"),
    MAIL_PORT            = int(os.getenv("MAIL_PORT", 587)),
    MAIL_USE_TLS         = os.getenv("MAIL_USE_TLS", "True") == "True",
    MAIL_USERNAME        = os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD        = os.getenv("MAIL_PASSWORD"),
    MAIL_DEFAULT_SENDER  = os.getenv("MAIL_DEFAULT_SENDER"),
)
mail = Mail(app)
 
# ====== MongoDB ======
client = MongoClient(MONGO_URI)
db     = client['auth_demo']
 
users         = db['users']
token_store   = db['tokens']   # unified collection for verify + reset tokens
 
# ====== TTL index: MongoDB auto-deletes expired tokens ======
token_store.create_index("expires_at", expireAfterSeconds=0)
 
 
# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
 
def is_valid_email(email: str) -> bool:
    return bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", email))
 
 
def create_token(token_type: str, email: str, ttl_minutes: int) -> str:
    """
    Persist a secure token in MongoDB and return its value.
    token_type: 'verify' | 'reset'
    """
    raw = secrets.token_urlsafe(32)
    token_store.delete_many({"email": email, "type": token_type})   # invalidate old tokens
    token_store.insert_one({
        "token":      raw,
        "type":       token_type,
        "email":      email,
        "expires_at": datetime.utcnow() + timedelta(minutes=ttl_minutes),
    })
    return raw
 
 
def consume_token(token_type: str, raw: str):
    """
    Validate + delete a token. Returns the email on success, None on failure.
    """
    entry = token_store.find_one({
        "token": raw,
        "type":  token_type,
        "expires_at": {"$gt": datetime.utcnow()},
    })
    if not entry:
        return None
    token_store.delete_one({"_id": entry["_id"]})
    return entry["email"]
 
 
def send_email(subject: str, recipient: str, body: str) -> bool:
    try:
        msg = Message(subject, recipients=[recipient])
        msg.body = body
        mail.send(msg)
        return True
    except Exception as e:
        print(f"[MAIL ERROR] {e}")
        return False
 
 
# ─────────────────────────────────────────────
#  USER AUTH API
# ─────────────────────────────────────────────
 
@app.route('/api/register', methods=['POST'])
def api_register():
    data     = request.json or {}
    username = (data.get('username') or '').strip()
    email    = (data.get('email')    or '').strip().lower()
    password =  data.get('password') or ''
 
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters.'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters.'}), 400
    if not is_valid_email(email):
        return jsonify({'error': 'Please provide a valid email address.'}), 400
    if users.find_one({'$or': [{'username': username}, {'email': email}]}):
        return jsonify({'error': 'Username or email already exists.'}), 409
 
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    users.insert_one({
        'username':      username,
        'email':         email,
        'password':      pw_hash,
        'emailVerified': False,
        'createdAt':     datetime.utcnow(),
    })
 
    raw_token   = create_token('verify', email, ttl_minutes=60)
    verify_link = f"{BASE_URL}/verify-email?token={raw_token}"
    send_email(
        "Verify Your Email",
        email,
        f"Hi {username},\n\nClick the link below to verify your account:\n\n{verify_link}\n\nThis link expires in 1 hour.\n\nIf you did not register, ignore this email."
    )
 
    return jsonify({'message': 'Registered successfully. Please check your email to verify your account.'}), 201
 
 
@app.route('/api/login', methods=['POST'])
def api_login():
    data     = request.json or {}
    username = (data.get('username') or '').strip()
    password =  data.get('password') or ''
 
    doc = users.find_one({'username': username})
    if not doc:
        return jsonify({'error': 'Invalid username or password.'}), 401
    if not doc.get('emailVerified'):
        return jsonify({'error': 'Please verify your email before logging in.'}), 403
    if not bcrypt.checkpw(password.encode(), doc['password']):
        return jsonify({'error': 'Invalid username or password.'}), 401
 
    return jsonify({
        'message': 'Login successful',
        'profile': {'username': doc['username'], 'email': doc['email']},
    }), 200
 
 
@app.route('/api/me/<username>', methods=['GET'])
def api_me(username):
    doc = users.find_one({'username': username})
    if not doc:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'profile': {'username': doc['username'], 'email': doc.get('email', '')}})
 
 
# ─────────────────────────────────────────────
#  EMAIL VERIFICATION
# ─────────────────────────────────────────────
 
@app.route('/verify-email')
def verify_email():
    raw   = request.args.get('token', '')
    email = consume_token('verify', raw)
 
    if not email:
        return "Invalid or expired verification link. Please register again.", 400
 
    users.update_one({'email': email}, {'$set': {'emailVerified': True}})
    return render_template('verify_success.html', email=email)
 
 
# ─────────────────────────────────────────────
#  FORGOT / RESET PASSWORD
# ─────────────────────────────────────────────
 
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data  = request.json or {}
    email = (data.get('email') or '').strip().lower()
 
    user = users.find_one({'email': email})
    if not user:
        # Don't reveal whether email exists
        return jsonify({'message': 'If that email is registered, a reset link has been sent.'}), 200
 
    raw_token  = create_token('reset', email, ttl_minutes=15)
    reset_link = f"{BASE_URL}/reset-password?token={raw_token}"
    ok = send_email(
        "Password Reset Request",
        email,
        f"Click the link below to reset your password:\n\n{reset_link}\n\nThis link expires in 15 minutes.\n\nIf you did not request this, ignore this email."
    )
 
    if not ok:
        return jsonify({'error': 'Failed to send email. Please try again later.'}), 500
 
    return jsonify({'message': 'If that email is registered, a reset link has been sent.'}), 200
 
 
@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data         = request.json or {}
    raw          = data.get('token', '')
    new_password = data.get('password', '')
 
    if not raw or not new_password:
        return jsonify({'error': 'Token and new password required.'}), 400
    if len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters.'}), 400
 
    email = consume_token('reset', raw)
    if not email:
        return jsonify({'error': 'Invalid or expired token. Please request a new reset link.'}), 400
 
    pw_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
    users.update_one({'email': email}, {'$set': {'password': pw_hash}})
 
    return jsonify({'message': 'Password reset successful. You can now log in.'}), 200
 
 
# ─────────────────────────────────────────────
#  ADMIN API
# ─────────────────────────────────────────────
 
def admin_required():
    """Return an error response tuple if not admin, else None."""
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    return None
 
 
@app.route('/api/admin/login', methods=['POST'])
def api_admin_login():
    data = request.json or {}
    if data.get("username") == ADMIN_USER and data.get("password") == ADMIN_PASS:
        session['admin'] = True
        return jsonify({"message": "Admin login successful"}), 200
    return jsonify({"error": "Invalid admin credentials"}), 401
 
 
@app.route('/api/admin/users', methods=['GET'])
def api_admin_users():
    err = admin_required()
    if err:
        return err
 
    # Only return VERIFIED users
    users_list = []
    for u in users.find({'emailVerified': True}, {"password": 0}):
        u["_id"] = str(u["_id"])
        if "createdAt" in u:
            u["createdAt"] = u["createdAt"].isoformat()
        users_list.append(u)
 
    return jsonify({'users': users_list})
 
 
@app.route('/api/admin/delete-user', methods=['DELETE'])
def api_admin_delete_user():
    err = admin_required()
    if err:
        return err
 
    data    = request.json or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "User ID is required"}), 400
 
    try:
        result = users.delete_one({"_id": ObjectId(user_id)})
    except Exception:
        return jsonify({"error": "Invalid user ID format"}), 400
 
    if result.deleted_count == 0:
        return jsonify({"error": "User not found"}), 404
 
    return jsonify({"message": f"User {user_id} deleted successfully"}), 200
 
 
@app.route('/api/admin/logout', methods=['POST'])
def api_admin_logout():
    session.pop('admin', None)
    return jsonify({"message": "Logged out"}), 200
 
 
# ─────────────────────────────────────────────
#  PAGE ROUTES
# ─────────────────────────────────────────────
 
@app.route('/')
def index():
    return render_template('login.html')
 
@app.route('/register')
def page_register():
    return render_template('register.html')
 
@app.route('/login')
def page_login():
    return render_template('login.html')
 
@app.route('/profile')
def page_profile():
    return render_template('profile.html')
 
@app.route('/admin')
def page_admin():
    return render_template('admin.html')
 
@app.route('/forgot-password')
def page_forgot_password():
    return render_template('forgot_password.html')
 
@app.route('/reset-password')
def page_reset_password():
    token = request.args.get('token', '')
    return render_template('reset_password.html', token=token)
 
 
# ─────────────────────────────────────────────
#  RUN
# ─────────────────────────────────────────────
 
if __name__ == '__main__':
    app.run(debug=True)