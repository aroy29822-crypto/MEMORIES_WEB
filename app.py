# app.py
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from datetime import datetime, timedelta
from bson import ObjectId
from dotenv import load_dotenv
import cloudinary
import cloudinary.uploader
import os
import random
import smtplib
from email.message import EmailMessage
import secrets
import string
from time import time

# ---------- Load env ----------
load_dotenv()

# ---------- Flask + DB ----------
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", secrets.token_hex(32))

MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["memories_db"]
users = db["users"]
posts = db["posts"]
feedbacks = db["feedbacks"]
login_logs = db["login_logs"]
logs = db["logs"]

# ---------- Cloudinary (optional for uploads) ----------
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi', 'mkv', 'webm'}
if os.getenv("CLOUD_NAME"):
    cloudinary.config(
        cloud_name=os.getenv("CLOUD_NAME"),
        api_key=os.getenv("CLOUD_API_KEY"),
        api_secret=os.getenv("CLOUD_API_SECRET")
    )

# ---------- Constants ----------
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "aroy29822@gmail.com")
PASSWORD_LENGTH = 12  # generated password length
OTP_TTL_MIN = 5  # minutes

# ---------- Security config ----------
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',   # set to 'Strict' if you want stricter behavior
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)
# NOTE: in production serve over HTTPS and set SESSION_COOKIE_SECURE = True


# ---------- Email helper ----------
def send_email(to, subject, body):
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = os.getenv("EMAIL_USER")
        msg["To"] = to
        msg.set_content(body)

        host = os.getenv("EMAIL_HOST", "smtp.gmail.com")
        port = int(os.getenv("EMAIL_PORT", 587))
        server = smtplib.SMTP(host, port)
        server.starttls()
        server.login(os.getenv("EMAIL_USER"), os.getenv("EMAIL_PASS"))
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print("MAIL ERROR:", e)
        return False


# ---------- Utility helpers ----------
def gen_password(length=PASSWORD_LENGTH):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def gen_otp():
    return str(random.randint(100000, 999999))


def log_action(user_email, action, details=None):
    try:
        logs.insert_one({
            "user": user_email,
            "action": action,
            "details": details or {},
            "time": datetime.utcnow()
        })
    except Exception:
        pass


def update_last_active(user_email):
    try:
        users.update_one({"email": user_email}, {"$set": {"last_active": datetime.utcnow()}})
    except Exception:
        pass


# ---------- CSRF (lightweight) ----------
def ensure_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def verify_csrf():
    token = session.get("csrf_token")
    form = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    return token and form and secrets.compare_digest(token, form)


def require_csrf(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if request.method == "POST":
            if not verify_csrf():
                flash("Invalid CSRF token.")
                return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped


# ---------- Simple in-memory rate limiting for login attempts ----------
_login_attempts = {}  # key: email_or_ip -> {count, first_ts, blocked_until}

def record_attempt(key, limit=6, window=300, block_duration=300):
    now = int(time())
    entry = _login_attempts.get(key, {"count": 0, "first": now, "blocked_until": 0})
    if now - entry["first"] > window:
        entry = {"count": 0, "first": now, "blocked_until": 0}
    if entry.get("blocked_until", 0) > now:
        _login_attempts[key] = entry
        return False, entry["blocked_until"]
    entry["count"] += 1
    if entry["count"] > limit:
        entry["blocked_until"] = now + block_duration
    _login_attempts[key] = entry
    return True, entry.get("blocked_until", 0)


# ---------- Decorators ----------
def require_active_user(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" in session:
            me = session["user"].lower()
            user = users.find_one({"email": me})
            if user:
                update_last_active(me)
            if user and user.get("blocked"):
                session.pop("user", None)
                flash("Your account was blocked by Admin. You’ve been logged out.")
                return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


@app.before_request
def check_blocked_user():
    safe_routes = ["login", "register", "static", "check_status", "send_reg_otp", "check_email"]
    if any(request.endpoint and r in request.endpoint for r in safe_routes):
        return
    if "user" in session:
        me = session["user"].lower()
        user = users.find_one({"email": me})
        if user:
            update_last_active(me)
        if user and user.get("blocked"):
            session.pop("user", None)
            flash("Your account was blocked by Admin. You have been logged out.")
            return redirect(url_for("login"))


@app.context_processor
def inject_common():
    return dict(ADMIN_EMAIL=ADMIN_EMAIL, csrf_token=ensure_csrf_token())


# ---------- ROUTES ----------

@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("feed"))
    return redirect(url_for("login"))


# ---------- LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
@require_csrf
def login():
    # GET: show login (if registration just happened we may autofill)
    if request.method == "GET":
        # check if there's a temp password stored (autofill after registration)
        temp_pass = session.pop("temp_password", None)  # popped so it's one-time
        temp_email = session.pop("temp_email", None)
        return render_template("login.html", prefill_email=temp_email, prefill_password=temp_pass)

    # POST: actual login
    email = request.form.get("email", "").lower().strip()
    password = request.form.get("password", "")

    # rate limiting key: email or remote addr
    key = email if email else request.remote_addr
    ok, blocked_until = record_attempt(key)
    if not ok:
        flash("Too many attempts. Try again later.")
        return redirect(url_for("login"))

    user = users.find_one({"email": email})
    if not user or not user.get("password"):
        flash("No such registered user or password not set. Please register first.")
        return redirect(url_for("login"))

    if user.get("blocked"):
        flash("Your account has been blocked by Admin.")
        return redirect(url_for("login"))

    if check_password_hash(user["password"], password):
        session["user"] = email
        session["just_logged"] = True
        users.update_one({"email": email}, {"$set": {"last_login": datetime.utcnow()}})
        # log login
        login_logs.insert_one({
            "user": email,
            "time": datetime.utcnow(),
            "ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", "")[:500],
            "action": "login"
        })
        return redirect(url_for("feed"))
    else:
        flash("Wrong password.")
        return redirect(url_for("login"))


# ---------- REGISTER (Auto-Pass) ----------
@app.route("/register", methods=["GET", "POST"])
@require_csrf
def register():
    if request.method == "GET":
        return render_template("register.html")

    # POST: create account and generate password
    first = request.form.get("first", "").strip()
    last = request.form.get("last", "").strip()
    email = request.form.get("email", "").lower().strip()

    if not first or not last:
        flash("First and last name are required.")
        return redirect(url_for("register"))

    # simple disposable domain check
    bad_domains = {"tempmail.com", "10minutemail.com", "yopmail.com", "mailinator.com", "guerrillamail.com"}
    domain = email.split("@")[-1].lower()
    if domain in bad_domains:
        flash("Disposable/temporary emails are not allowed.")
        return redirect(url_for("register"))

    if users.find_one({"email": email}):
        flash("This email is already registered.")
        return redirect(url_for("register"))

    # generate secure password and email it
    generated = gen_password()
    hashed = generate_password_hash(generated)

    users.insert_one({
        "first_name": first,
        "last_name": last,
        "email": email,
        "password": hashed,
        "created_at": datetime.utcnow(),
        "last_login": None,
        "last_active": None,
        "last_ip": None
    })

    # send email with the generated password
    sent = send_email(email, "Your Memories account — generated password", f"Hello {first},\n\n"
                      f"An account was created using this email. Your temporary password is:\n\n"
                      f"{generated}\n\n"
                      f"Use that to log in (you can change it later from settings).\n\nThanks,\nMemories Team")

    # store one-time autofill in session (so we don't expose via url)
    session["temp_password"] = generated
    session["temp_email"] = email

    flash("Account created. We've emailed a generated password to you.")
    return redirect(url_for("login"))

import secrets
import string

def generate_secure_password(length=12):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    # ensure at least one lowercase, one uppercase, one digit
    while True:
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)):
            return pwd

@app.post("/auto_register")
def auto_register():
    """
    Create account + auto-generate a password, email it to user,
    store only hashed password in DB, set must_change_password flag.
    Frontend expects JSON: {status: "ok"} or {status:"error", msg:"..."}
    """
    first = request.form.get("first", "").strip()
    last = request.form.get("last", "").strip()
    email = request.form.get("email", "").lower().strip()

    # Basic checks
    if not first or not email:
        return jsonify({"status": "error", "msg": "First name and email required."}), 400

    if "@" not in email:
        return jsonify({"status": "error", "msg": "Invalid email."}), 400

    # restrict to Gmail if you require that
    domain = email.split("@", 1)[-1].lower()
    if domain != "gmail.com":
        return jsonify({"status": "error", "msg": "Only Gmail accounts allowed."}), 400

    # disposable domains blocklist (same as check_email)
    bad_domains = {
        "tempmail.com", "10minutemail.com", "yopmail.com", "mailinator.com",
        "guerrillamail.com", "sharklasers.com", "getnada.com", "dispostable.com"
    }
    if domain in bad_domains:
        return jsonify({"status": "error", "msg": "Disposable/temporary email not allowed."}), 400

    # Prevent duplicate
    if users.find_one({"email": email}):
        return jsonify({"status": "error", "msg": "Email already registered."}), 409

    # generate secure temporary password
    plain_password = generate_secure_password(12)

    # store hashed password only
    hashed = generate_password_hash(plain_password)

    user_doc = {
        "first_name": first,
        "last_name": last,
        "email": email,
        "password": hashed,
        "created_at": datetime.utcnow(),
        "last_login": None,
        "must_change_password": True,     # force user to change on first login
        "auto_password_created": True,
    }

    try:
        users.insert_one(user_doc)
    except Exception as e:
        return jsonify({"status": "error", "msg": "DB error: could not create user."}), 500

    # send email with temp password (plaintext)
    subject = "Welcome — your account password"
    body = (
        f"Hi {first or ''},\n\n"
        "Thanks for registering. We generated a secure temporary password for you:\n\n"
        f"    {plain_password}\n\n"
        "You can use this to login immediately. For security, we require that you change this password "
        "on your first login (you'll see an option to Create New Password or Continue with this one).\n\n"
        "If you didn't request this, ignore this email.\n\n"
        "— Memories Team"
    )

    sent = send_email(email, subject, body)
    if not sent:
        # remove the user we inserted (avoid orphan)
        try:
            users.delete_one({"email": email})
        except Exception:
            pass
        return jsonify({"status": "error", "msg": "Failed to send email. Try again later."}), 500

    log_action(email, "auto_register", {"first": first, "last": last})
    return jsonify({"status": "ok"})


# ---------- Check email endpoint (AJAX) ----------
@app.route("/check_email")
def check_email():
    email = request.args.get("email", "").lower().strip()
    if email == "":
        return jsonify({"status": "empty"})
    bad_domains = {"tempmail.com", "10minutemail.com", "yopmail.com", "mailinator.com"}
    if email.split("@")[-1].lower() in bad_domains:
        return jsonify({"status": "disposable"})
    if users.find_one({"email": email}):
        return jsonify({"status": "exists"})
    return jsonify({"status": "ok"})


# ---------- SEND REG OTP (fallback option; not used by default) ----------
@app.post("/send_reg_otp")
def send_reg_otp():
    email = request.form.get("email", "").lower().strip()
    if users.find_one({"email": email}):
        return jsonify({"status": "exists"})
    otp = gen_otp()
    users.update_one({"email": email}, {"$set": {"reg_otp": otp, "reg_otp_expiry": datetime.utcnow() + timedelta(minutes=OTP_TTL_MIN)}}, upsert=True)
    ok = send_email(email, "Your registration OTP", f"Your OTP is {otp} valid for {OTP_TTL_MIN} minutes.")
    return jsonify({"status": "sent" if ok else "email-error"})


# ---------- FORGOT / RESET password (Mongo only) ----------
@app.route("/forgot_password", methods=["GET", "POST"])
@require_csrf
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")
    email = request.form.get("email", "").lower().strip()
    user = users.find_one({"email": email})
    if not user:
        flash("No account found with that email.")
        return redirect(url_for("forgot_password"))

    otp = gen_otp()
    users.update_one({"email": email}, {"$set": {"reset_otp": otp, "reset_expiry": datetime.utcnow() + timedelta(minutes=OTP_TTL_MIN)}})
    send_email(email, "Reset OTP for Memories", f"Your OTP to reset password is {otp}. Valid for {OTP_TTL_MIN} minutes.")
    flash("OTP sent to your email.")
    return redirect(url_for("reset_verify", email=email))


@app.route("/reset_verify/<email>", methods=["GET", "POST"])
@require_csrf
def reset_verify(email):
    email = email.lower()
    user = users.find_one({"email": email})
    if not user:
        flash("Invalid request.")
        return redirect(url_for("login"))
    if request.method == "GET":
        return render_template("reset_verify.html", email=email)
    otp = request.form.get("otp", "").strip()
    user = users.find_one({"email": email})
    if "reset_otp" not in user:
        flash("No OTP found. Request a new one.")
        return redirect(url_for("forgot_password"))
    if datetime.utcnow() > user.get("reset_expiry", datetime.utcnow()):
        flash("OTP expired.")
        return redirect(url_for("forgot_password"))
    if otp != user.get("reset_otp"):
        flash("Wrong OTP.")
        return redirect(url_for("reset_verify", email=email))
    # OTP ok
    return redirect(url_for("reset_password", email=email))


@app.route("/reset_password/<email>", methods=["GET", "POST"])
@require_csrf
def reset_password(email):
    email = email.lower()
    user = users.find_one({"email": email})
    if not user:
        flash("Invalid request.")
        return redirect(url_for("login"))
    if request.method == "GET":
        return render_template("reset_password.html", email=email)
    new_pass = request.form.get("password", "")
    if len(new_pass) < 5:
        flash("Password must be at least 5 characters.")
        return redirect(url_for("reset_password", email=email))
    users.update_one({"email": email}, {"$set": {"password": generate_password_hash(new_pass)}, "$unset": {"reset_otp": "", "reset_expiry": ""}})
    flash("Password updated successfully. Login now.")
    return redirect(url_for("login"))


# ---------- Admin reset password (Mongo only) ----------
@app.route("/admin/reset_password/<email>", methods=["GET", "POST"])
@require_csrf
def admin_reset_password(email):
    if "user" not in session or session.get("user", "").lower() != ADMIN_EMAIL.lower():
        flash("Admin only.")
        return redirect(url_for("login"))
    email = email.lower()
    user = users.find_one({"email": email})
    if not user:
        flash("User not found.")
        return redirect(url_for("admin_users"))
    if request.method == "GET":
        return render_template("admin_reset_password.html", email=email)
    # generate a new password and email it
    new_pass = gen_password()
    users.update_one({"email": email}, {"$set": {"password": generate_password_hash(new_pass)}})
    send_email(email, "Your password was reset", f"Your new password: {new_pass}\nYou can change it after login.")
    flash(f"Password reset and emailed to {email}.")
    return redirect(url_for("admin_users"))


# ---------- Upload, feed, profile, edit, delete (same behavior) ----------
@app.route("/upload", methods=["GET", "POST"])
@require_active_user
@require_csrf
def upload():
    if request.method == "GET":
        return render_template("upload.html")
    file = request.files.get("file")
    place = request.form.get("place", "").strip()
    date = request.form.get("date", "").strip()
    desc = request.form.get("desc", "").strip()
    if not file or file.filename == "":
        flash("Select a file.")
        return redirect(url_for("upload"))
    ext = file.filename.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_EXT:
        flash("File type not allowed.")
        return redirect(url_for("upload"))
    raw = file.read()
    if len(raw) > 100 * 1024 * 1024:
        flash("File too large (Max 100 MB).")
        return redirect(url_for("upload"))
    file.seek(0)
    up = cloudinary.uploader.upload(file, resource_type="auto")
    url = up["secure_url"]
    posts.insert_one({
        "owner": session["user"].lower(),
        "url": url,
        "place": place,
        "date": date,
        "desc": desc,
        "time": datetime.utcnow()
    })
    log_action(session["user"], "upload", {"url": url, "place": place})
    flash("Uploaded successfully.")
    return redirect(url_for("feed"))


@app.route("/feed")
@require_active_user
def feed():
    me = session["user"].lower()
    user = users.find_one({"email": me})
    docs = list(posts.find().sort("time", -1))
    firstname = (user or {}).get("first_name", "Friend")
    show_popup = session.pop("just_logged", None)
    return render_template("feed.html", docs=docs, firstname=firstname, show_popup=show_popup)


@app.route("/profile")
@require_active_user
def profile():
    me = session["user"].lower()
    docs = list(posts.find({"owner": me}).sort("time", -1))
    return render_template("profile.html", me=me, docs=docs)


@app.route("/edit/<id>", methods=["GET", "POST"])
@require_csrf
def edit_post(id):
    if "user" not in session:
        return redirect(url_for("login"))
    me = session["user"].lower()
    try:
        doc = posts.find_one({"_id": ObjectId(id)})
    except Exception:
        doc = None
    if not doc:
        flash("Post not found.")
        return redirect(url_for("feed"))
    if doc.get("owner") != me and me != ADMIN_EMAIL.lower():
        flash("No permission.")
        return redirect(url_for("feed"))
    if request.method == "POST":
        new_desc = request.form.get("desc", "").strip()
        new_place = request.form.get("place", "").strip()
        new_date = request.form.get("date", "").strip()
        posts.update_one({"_id": doc["_id"]}, {"$set": {"desc": new_desc, "place": new_place, "date": new_date}})
        flash("Updated successfully.")
        return redirect(url_for("admin") if me == ADMIN_EMAIL.lower() else url_for("profile"))
    return render_template("edit.html", doc=doc)


@app.post("/delete/<id>")
@require_csrf
def delete_post(id):
    if "user" not in session or session.get("user", "").lower() != ADMIN_EMAIL.lower():
        flash("Admin only.")
        return redirect(url_for("feed"))
    try:
        posts.delete_one({"_id": ObjectId(id)})
        flash("Post deleted successfully.")
    except Exception:
        flash("Failed to delete.")
    return redirect(url_for("admin"))


# ---------- Admin pages ----------
@app.route("/admin")
def admin():
    if "user" not in session:
        return redirect(url_for("login"))
    if session.get("user", "").lower() != ADMIN_EMAIL.lower():
        flash("Admin only")
        return redirect(url_for("feed"))
    docs = list(posts.find().sort("time", -1))
    return render_template("admin.html", docs=docs)


@app.route("/admin/overview")
def admin_overview():
    if "user" not in session:
        return redirect(url_for("login"))
    if session.get("user", "").lower() != ADMIN_EMAIL.lower():
        return redirect(url_for("login"))
    users_list = list(users.find({}, {"password": 0}).sort("created_at", -1))
    recent_logs = list(logs.find().sort("time", -1).limit(200))
    total_users = users.count_documents({})
    total_posts = posts.count_documents({})
    return render_template("admin_overview.html", users=users_list, logs=recent_logs, total_users=total_users, total_posts=total_posts)


@app.route("/admin/users")
def admin_users():
    if "user" not in session:
        return redirect(url_for("login"))
    if session.get("user", "").lower() != ADMIN_EMAIL.lower():
        flash("Admin only.")
        return redirect(url_for("feed"))
    all_users = list(users.find().sort("created_at", -1))
    threshold = datetime.utcnow() - timedelta(minutes=3)
    for u in all_users:
        last_active = u.get("last_active")
        u["is_online"] = bool(last_active and last_active >= threshold)
        # remove sensitive fields for templates
        u.pop("password", None)
    return render_template("admin_users.html", users=all_users)


# ---------- Admin live stats endpoint (returns serializable data) ----------
@app.route("/admin/live_stats")
def admin_live_stats():
    if "user" not in session or session.get("user", "").lower() != ADMIN_EMAIL.lower():
        return jsonify({"error": "unauthorized"}), 403

    total_users = users.count_documents({})
    total_posts = posts.count_documents({})
    total_feedback = feedbacks.count_documents({})

    # all users
    all_users = list(users.find({}, {"email": 1, "last_active": 1, "_id": 0}))
    for u in all_users:
        if u.get("last_active"):
            u["last_active"] = u["last_active"].isoformat()

    # recent logins (serialize)
    recent_logins_raw = list(login_logs.find().sort("time", -1).limit(10))
    recent_logins = [{"user": x["user"], "action": x.get("action", ""), "time": x["time"].strftime("%H:%M:%S %d-%b")} for x in recent_logins_raw]

    # recent uploads (serialize)
    recent_uploads_raw = list(posts.find().sort("time", -1).limit(5))
    recent_uploads = [{"owner": x["owner"], "time": x["time"].strftime("%H:%M:%S %d-%b")} for x in recent_uploads_raw]

    return jsonify({
        "total_users": total_users,
        "total_posts": total_posts,
        "total_feedback": total_feedback,
        "online_users": [u["email"] for u in all_users if u.get("last_active")],
        "recent_logins": recent_logins,
        "recent_uploads": recent_uploads,
        "all_users": all_users
    })


# ---------- Heartbeat ----------
@app.route("/heartbeat")
def heartbeat():
    if "user" not in session:
        return jsonify({"status": "no_session"})
    me = session["user"].lower()
    users.update_one({"email": me}, {"$set": {"last_active": datetime.utcnow()}})
    return jsonify({"status": "ok"})


# ---------- Run ----------
if __name__ == "__main__":
    app.run(debug=True)
