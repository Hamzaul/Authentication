import token

from flask import Flask, request, jsonify, render_template, session, url_for
from flask_cors import CORS
from flask_mail import Mail, Message
from pymongo import MongoClient
from bson import ObjectId
import bcrypt, os, secrets, re
from datetime import datetime, timedelta
from dotenv import load_dotenv

# ====== Load env ======
load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app, origins="*") # allow frontend (Live Server)
app.secret_key = os.getenv("SECRET_KEY", "devsecret")

# ====== Config ======
MONGO_URI = os.getenv('MONGO_URI')
ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASS = os.getenv("ADMIN_PASS")

# ====== Mail Setup ======
app.config.update(
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_PORT=int(os.getenv("MAIL_PORT", 587)),
    MAIL_USE_TLS=os.getenv("MAIL_USE_TLS", "True") == "True",
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_DEFAULT_SENDER=os.getenv("MAIL_DEFAULT_SENDER")
)
mail = Mail(app)

# ====== Mongo ======
client = MongoClient(MONGO_URI)
db = client['auth_demo']
users = db['users']

# ====== Tokens ======
reset_tokens = {}
verify_tokens = {}

# ============================
#       USER AUTH API
# ============================
def is_valid_email(email):
    return re.match(r"^[^@]+@[^@]+\.[^@]+$", email)

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.json or {}
    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters.'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters.'}), 400
    if not is_valid_email(email):
        return jsonify({'error': 'Please provide a valid email address.'}), 400

    if users.find_one({'$or': [{'username': username}, {'email': email}]}):
        return jsonify({'error': 'Username or email already exists.'}), 409

    pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users.insert_one({
        'username': username,
        'email': email,
        'password': pw_hash,
        'emailVerified': False
    })

    # generate email verification token
    token = secrets.token_urlsafe(32)
    verify_tokens[token] = {
        'email': email,
        'expires': datetime.utcnow() + timedelta(hours=1)
    }
    BASE_URL = "https://authentication-eng2.onrender.com"
    verify_link = f"{BASE_URL}/verify-email?token={token}"

    try:
        msg = Message("Verify Your Email", recipients=[email])
        msg.body = f"Click to verify your account:\n\n{verify_link}\n\nThis link expires in 1 hour."
        mail.send(msg)
    except Exception as e:
        print("Email send failed:", e)

    return jsonify({'message': 'Registered successfully. Please check your email to verify your account.'}), 201


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    doc = users.find_one({'username': username})
    if not doc:
        return jsonify({'error': 'Invalid username or password.'}), 401

    if not doc.get('emailVerified'):
        return jsonify({'error': 'Please verify your email before logging in.'}), 403

    if bcrypt.checkpw(password.encode('utf-8'), doc['password']):
        profile = {k: doc.get(k) for k in ['username', 'email']}
        return jsonify({'message': 'Login successful', 'profile': profile}), 200

    return jsonify({'error': 'Invalid username or password.'}), 401


@app.route('/api/me/<username>', methods=['GET'])
def api_me(username):
    doc = users.find_one({'username': username})
    if not doc:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'profile': {'username': doc['username'], 'email': doc.get('email', '')}})


# ============================
#   EMAIL VERIFICATION
# ============================
@app.route('/verify-email')
def verify_email():
    token = request.args.get('token')
    entry = verify_tokens.get(token)

    if not entry:
        return "Invalid or expired verification link", 400
    if entry['expires'] < datetime.utcnow():
        del verify_tokens[token]
        return "Verification link expired", 400

    email = entry['email']
    users.update_one({'email': email}, {'$set': {'emailVerified': True}})
    del verify_tokens[token]

    return render_template('verify_success.html', email=email)


# ============================
#   FORGOT / RESET PASSWORD
# ============================
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json or {}
    email = (data.get('email') or '').strip().lower()

    user = users.find_one({'email': email})
    if not user:
        return jsonify({'error': 'No account with that email'}), 404

    token = secrets.token_urlsafe(32)
    reset_tokens[token] = {
        'email': email,
        'expires': datetime.utcnow() + timedelta(minutes=15)
    }

    BASE_URL = "https://authentication-eng2.onrender.com"
    reset_link = f"{BASE_URL}/reset-password?token={token}"

    try:
        msg = Message("Password Reset Request", recipients=[email])
        msg.body = f"Click the link below to reset your password:\n\n{reset_link}\n\nThis link expires in 15 minutes."
        mail.send(msg)
        return jsonify({'message': 'Password reset link sent to your email.'}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to send email: {str(e)}'}), 500


@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.json or {}
    token = data.get('token')
    new_password = data.get('password')

    if not token or not new_password:
        return jsonify({'error': 'Token and new password required'}), 400

    entry = reset_tokens.get(token)
    if not entry:
        return jsonify({'error': 'Invalid or expired token'}), 400
    if entry['expires'] < datetime.utcnow():
        del reset_tokens[token]
        return jsonify({'error': 'Token expired'}), 400

    email = entry['email']
    pw_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    users.update_one({'email': email}, {'$set': {'password': pw_hash}})
    del reset_tokens[token]

    return jsonify({'message': 'Password reset successful.'}), 200


# ============================
#        ADMIN API
# ============================
@app.route('/api/admin/login', methods=['POST'])
def api_admin_login():
    data = request.json or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if username == ADMIN_USER and password == ADMIN_PASS:
        session['admin'] = True
        return jsonify({"message": "Admin login successful"}), 200

    return jsonify({"error": "Invalid admin credentials"}), 401


@app.route('/api/admin/users', methods=['GET'])
def api_admin_users():
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    users_list = []
    for u in users.find({}, {"password": 0}):
        u["_id"] = str(u["_id"])
        users_list.append(u)

    return jsonify({'users': users_list})


@app.route('/api/admin/delete-user', methods=['DELETE'])
def api_admin_delete_user():
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json or {}
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


# ============================
#           PAGES
# ============================
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
    token = request.args.get('token')
    return render_template('reset_password.html', token=token)


# ====== Run ======

if __name__ == '__main__':
    app.run(debug=True)

