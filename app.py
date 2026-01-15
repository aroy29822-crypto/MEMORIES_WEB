# app.py
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from datetime import timedelta
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
from flask_socketio import SocketIO, emit
from flask import send_from_directory
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
# ---------- Load env ----------
load_dotenv()

# ---------- Flask + DB ----------
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", secrets.token_hex(32))
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="eventlet",
    manage_session=True
)


MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["memories_db"]
users = db["users"]
posts = db["posts"]
feedbacks = db["feedbacks"]
login_logs = db["login_logs"]
logs = db["logs"]

def utcnow():
    return datetime.now(timezone.utc)


# ---------- Cloudinary (optional for uploads) ----------
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi', 'mkv', 'webm'}
if os.getenv("CLOUD_NAME"):
    cloudinary.config(
        cloud_name=os.getenv("CLOUD_NAME"),
        api_key=os.getenv("CLOUD_API_KEY"),
        api_secret=os.getenv("CLOUD_API_SECRET")
    )

# ---------- Constants ----------
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "sumanta7654@gmail.com")
PASSWORD_LENGTH = 12  # generated password length
OTP_TTL_MIN = 5  # minutes

# ---------- Security config ----------
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',   # set to 'Strict' if you want stricter behavior
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)
# NOTE: in production serve over HTTPS and set SESSION_COOKIE_SECURE = True



UPLOAD_FOLDER = "static/uploads/profiles"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/profile/upload", methods=["POST"])
def upload_profile_pic():
    if "user" not in session:
        return {"error": "unauthorized"}, 401

    file = request.files.get("file")
    if not file or not allowed_file(file.filename):
        return {"error": "invalid file"}, 400

    filename = secure_filename(session["user"] + "_" + file.filename)
    path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(path)

    db.users.update_one(
        {"email": session["user"]},
        {"$set": {"profile_pic": "/" + path}}
    )

    return {"url": "/" + path}


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
            "time": utcnow()
        })
    except Exception:
        pass


def update_last_active(user_email):
    try:
        users.update_one({"email": user_email}, {"$set": {"last_active": utcnow()}})
    except Exception:
        pass

'''
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

'''
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
    safe_endpoints = {
        "login", "register", "static",
        "check_status", "check_email",
        "admin_live", "admin_live_stats",
        "admin_overview", "admin_users",
        "admin_feedback", "admin",
        "admin_user_profile"
    }

    if request.endpoint in safe_endpoints:
        return

    if "user" in session:
        me = session["user"].lower()
        user = users.find_one({"email": me})

        if user:
            update_last_active(me)

        if user and user.get("blocked"):
            session.clear()
            flash("Your account was blocked by Admin.")
            return redirect(url_for("login"))


@app.context_processor
def inject_common():
    return dict(ADMIN_EMAIL=ADMIN_EMAIL,)


# ---------- ROUTES ----------

@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("feed"))
    return redirect(url_for("login"))


# ---------- LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").lower().strip()
    password = request.form.get("password", "")

    user = users.find_one({"email": email})
    if not user:
        flash("Invalid email or password.")
        return redirect(url_for("login"))

    if not check_password_hash(user["password"], password):
        flash("Invalid email or password.")
        return redirect(url_for("login"))

    session["user"] = email
    session["just_logged"] = True
    users.update_one({"email": email}, {"$set": {"last_login": utcnow()}})
    login_logs.insert_one({
        "user": email,
        "action": "login",
        "time": utcnow()
    })
    
    return redirect(url_for("feed"))

@app.route("/logout")
def logout():
    if "user" in session:
        login_logs.insert_one({
            "user": session["user"],
            "action": "logout",
            "time": utcnow()
        })
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    first = request.form.get("first", "").strip()
    last = request.form.get("last", "").strip()
    email = request.form.get("email", "").lower().strip()
    password = request.form.get("password", "")

    if not first or not last or not email or not password:
        flash("All fields are required.")
        return redirect(url_for("register"))

    if users.find_one({"email": email}):
        flash("Email already registered.")
        return redirect(url_for("register"))

    users.insert_one({
        "first_name": first,
        "last_name": last,
        "email": email,
        "password": generate_password_hash(password),
        "created_at": utcnow()

    })
    
    # ✅ AUTO LOGIN AFTER REGISTER
    session["user"] = email
    session["just_logged"] = True   # welcome popup থাকলে কাজে লাগবে
    
    flash("Welcome! Your account has been created 🎉")
    return redirect(url_for("feed"))
    

@socketio.on("typing")
def typing():
    if "user" not in session:
        return

    emit("show_typing", {
        "user": session["user"].split("@")[0]
    }, broadcast=True, include_self=False)


@socketio.on("stop_typing")
def stop_typing():
    emit("hide_typing", broadcast=True, include_self=False)



# ---------- FORGOT / RESET password (Mongo only) ----------
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")
    email = request.form.get("email", "").lower().strip()
    user = users.find_one({"email": email})
    if not user:
        flash("No account found with that email.")
        return redirect(url_for("forgot_password"))

    otp = gen_otp()
    users.update_one({"email": email}, {"$set": {"reset_otp": otp, "reset_expiry": utcnow() + timedelta(minutes=OTP_TTL_MIN)}})
    send_email(email, "Reset OTP for Memories", f"Your OTP to reset password is {otp}. Valid for {OTP_TTL_MIN} minutes.")
    flash("OTP sent to your email.")
    return redirect(url_for("reset_verify", email=email))


@app.route("/reset_verify/<email>", methods=["GET", "POST"])
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
    if utcnow() > user.get("reset_expiry", utcnow()):
        flash("OTP expired.")
        return redirect(url_for("forgot_password"))
    if otp != user.get("reset_otp"):
        flash("Wrong OTP.")
        return redirect(url_for("reset_verify", email=email))
    # OTP ok
    return redirect(url_for("reset_password", email=email))


@app.route("/reset_password/<email>", methods=["GET", "POST"])
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

community_messages = db["community_messages"]


#-------community-chats--------
@app.route("/community")
def community():
    if "user" not in session:
        return redirect(url_for("login"))
    
    messages = []
    
    for m in db.community_messages.find().sort("created_at", 1):
        m["id"] = str(m["_id"])
    
        # 🔥 FORCE ISO STRING WITH TZ
        if isinstance(m.get("created_at"), datetime):
            m["created_at"] = m["created_at"].astimezone(timezone.utc).isoformat()
    
        user = users.find_one({"email": m["user"]})
        m["unseen"] = session["user"] not in m.get("seen_by", [])      
        m["profile_pic"] = user.get("profile_pic") if user else None
        m["is_me"] = (m["user"] == session["user"])
        m["status"] = m.get("status", "sent")
        m["edited"] = m.get("edited", False)
    
        messages.append(m)

    return render_template("community.html", messages=messages)



#------------------Socket-Events---------------
@socketio.on("send_message")
def send_message(data):
    user_email = session.get("user")
    if not user_email:
        return

    user = users.find_one({"email": user_email})

    msg = {
        "user": user_email,
        "name": user.get("first_name", "User"),
        "text": data.get("text", ""),
        "file": data.get("file"),
        "created_at": utcnow(),
        "status": "sent",
        "seen_by": []
    }

    # ✅ INSERT + GET ID
    result = db.community_messages.insert_one(msg)
    msg_id = result.inserted_id

    # ✅ mark delivered
    db.community_messages.update_one(
        {"_id": msg_id},
        {"$set": {"status": "delivered"}}
    )

    emit("new_message", {
        "id": str(msg_id),
        "user": msg["user"],
        "profile_pic": user.get("profile_pic") if user else None,
        "text": msg["text"],
        "file": msg["file"],
        "created_at": msg["created_at"].astimezone(timezone.utc).isoformat(),
        "status": "delivered",
        "edited": False
    }, broadcast=True)



#---------seen-logic-----------
@socketio.on("mark_seen")
def mark_seen():
    viewer = session.get("user")
    if not viewer:
        return

    db.community_messages.update_many(
        {
            "user": {"$ne": viewer},
            "seen_by": {"$ne": viewer}
        },
        {
            "$addToSet": {"seen_by": viewer},
            "$set": {"status": "seen"}
        }
    )

    emit("messages_seen", {
        "user": viewer
    }, broadcast=True)





#------------------Socket-Edit-Rules------------
@socketio.on("edit_message")
def edit_message(data):
    user = session.get("user")
    if not user:
        return

    msg = db.community_messages.find_one({
        "_id": ObjectId(data["id"])
    })

    if not msg:
        return

    # ❌ অন্যের message edit করা যাবে না
    if msg["user"] != user:
        return

    # ❌ 10 মিনিট পার হলে edit না
    if utcnow() - msg["created_at"] > timedelta(minutes=10):
        emit("edit_failed", {"reason": "time_expired"})
        return

    db.community_messages.update_one(
        {"_id": msg["_id"]},
        {"$set": {
            "text": data["text"],
            "edited": True
        }}
    )

    emit("message_edited", {
        "id": data["id"],
        "text": data["text"],
        "edited": True
    }, broadcast=True)

@app.route("/community/info")
def community_info():
    if "user" not in session:
        return redirect(url_for("login"))

    all_users = list(users.find({}, {
        "first_name": 1,
        "last_name": 1,
        "email": 1,
        "profile_pic": 1,
        "last_active": 1
    }))

    now = utcnow()
    online_threshold = now - timedelta(minutes=3)

    for u in all_users:
        last = u.get("last_active")

        if last:
            # 🔥 if last is naive → make it UTC aware
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
        
            u["online"] = last >= online_threshold
        else:
            u["online"] = False


    return render_template("community_info.html", users=all_users)


@app.route("/user/<email>")
def public_user_profile(email):
    email = email.lower()

    user = users.find_one({"email": email})
    if not user:
        flash("User not found")
        return redirect(url_for("community"))

    # user posts
    docs = list(posts.find({"owner": email}).sort("time", -1))

    return render_template(
        "public_profile.html",
        user=user,
        docs=docs
    )


from werkzeug.utils import secure_filename

@app.route("/uploads/avatar/<filename>")
def serve_avatar(filename):
    return send_from_directory("uploads/avatar", filename)


AVATAR_FOLDER = "uploads/avatar"
os.makedirs(AVATAR_FOLDER, exist_ok=True)

@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    if "user" not in session:
        return redirect(url_for("login"))

    file = request.files.get("avatar")
    if not file or file.filename == "":
        return redirect(url_for("profile"))

    ext = file.filename.rsplit(".", 1)[-1].lower()
    if ext not in {"png", "jpg", "jpeg"}:
        flash("Only image files allowed")
        return redirect(url_for("profile"))

    filename = secure_filename(f"{session['user']}_{int(time())}.{ext}")
    path = os.path.join(AVATAR_FOLDER, filename)
    file.save(path)

    users.update_one(
        {"email": session["user"]},
        {"$set": {"profile_pic": f"/uploads/avatar/{filename}"}}
    )
    

    return redirect(url_for("profile"))


#------------upload-allowed-------------
UPLOAD_FOLDER = "uploads/chat"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_CHAT_FILES = {
    "png", "jpg", "jpeg", "gif",
    "pdf", "doc", "docx",
    "zip", "rar", "txt"
}


#-----------uploads-------------
@app.route("/chat/upload", methods=["POST"])
def chat_upload():
    if "user" not in session:
        return jsonify({"error": "login required"}), 401

    file = request.files.get("file")
    if not file or file.filename == "":
        return jsonify({"error": "no file"}), 400

    ext = file.filename.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_CHAT_FILES:
        return jsonify({"error": "file not allowed"}), 400

    filename = f"{int(time())}_{secure_filename(file.filename)}"
    path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(path)

    return jsonify({
        "url": f"/uploads/chat/{filename}",
        "name": file.filename,
        "type": ext
    })

@app.route("/uploads/chat/<filename>")
def serve_chat_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


# ---------- Admin reset password (Mongo only) ----------
@app.route("/admin/reset_password/<email>", methods=["GET", "POST"])
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

@app.route("/admin/live")
def admin_live():
    if "user" not in session or session.get("user","").lower() != ADMIN_EMAIL.lower():
        flash("Admin only.")
        return redirect(url_for("login"))

    return render_template("admin_live.html")


# ---------- Upload, feed, profile, edit, delete (same behavior) ----------
@app.route("/upload", methods=["GET", "POST"])
@require_active_user
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
        "time": utcnow()
    })
    log_action(session["user"], "upload", {"url": url, "place": place})
    flash("Uploaded successfully.")
    return redirect(url_for("feed"))


@app.route("/feed")
def feed():
    if "user" not in session:
        return redirect(url_for("login"))

    user = users.find_one({"email": session["user"]})
    show_popup = session.pop("just_logged", None)

    return render_template(
        "feed.html",
        firstname=user.get("first_name", "Friend"),
        show_popup=show_popup
    )


@app.route("/profile")
@require_active_user
def profile():
    me = session["user"].lower()
    docs = list(posts.find({"owner": me}).sort("time", -1))
    user = users.find_one({"email": me})

    return render_template(
        "profile.html",
        me=me,
        user=user,
        docs=docs
    )
    


@app.route("/edit/<id>", methods=["GET", "POST"])
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


@app.route("/feedback", methods=["POST"])
def submit_feedback():
    if "user" not in session:
        return redirect(url_for("login"))

    msg = request.form.get("msg", "").strip()
    if not msg:
        flash("Feedback cannot be empty.")
        return redirect(request.referrer or url_for("feed"))

    feedbacks.insert_one({
        "email": session["user"],
        "msg": msg,
        "time": utcnow()
    })

    flash("Thanks for your lovely feedback ❤️")
    return redirect(request.referrer or url_for("feed"))


@app.post("/delete/<id>")
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

@app.route("/admin/feedback")
def admin_feedback():
    if "user" not in session or session.get("user","").lower() != ADMIN_EMAIL.lower():
        flash("Admin only.")
        return redirect(url_for("login"))

    all_feedbacks = list(feedbacks.find().sort("time", -1))
    return render_template(
        "feedback_admin.html",
        feedbacks=all_feedbacks
    )

@app.post("/admin/block/<email>")
def admin_block_user(email):
    if "user" not in session or session.get("user","").lower() != ADMIN_EMAIL.lower():
        flash("Admin only.")
        return redirect(url_for("login"))

    email = email.lower()

    if email == ADMIN_EMAIL.lower():
        flash("Admin cannot block himself.")
        return redirect(url_for("admin_users"))

    user = users.find_one({"email": email})
    if not user:
        flash("User not found.")
        return redirect(url_for("admin_users"))

    new_status = not user.get("blocked", False)
    users.update_one({"email": email}, {"$set": {"blocked": new_status}})

    flash(f"User {'blocked' if new_status else 'unblocked'} successfully.")
    return redirect(url_for("admin_users"))


@app.route("/check_status")
def check_status():
    if "user" not in session:
        return jsonify({"status": "no_user"})
    user = users.find_one({"email": session["user"]})
    if user and user.get("blocked"):
        return jsonify({"status": "blocked"})
    return jsonify({"status": "ok"})


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
    threshold = utcnow() - timedelta(minutes=3)
    for u in all_users:
        last_active = u.get("last_active")
        u["is_online"] = bool(last_active and last_active >= threshold)
        # remove sensitive fields for templates
        u.pop("password", None)
    return render_template("admin_users.html", users=all_users)


@app.route("/admin/user/<email>")
def admin_user_profile(email):
    # admin check
    if "user" not in session or session.get("user", "").lower() != ADMIN_EMAIL.lower():
        flash("Admin only.")
        return redirect(url_for("login"))

    email = email.lower()

    # user posts
    docs = list(posts.find({"owner": email}).sort("time", -1))

    if not docs:
        flash("No posts found for this user.")

    return render_template(
        "admin_user_profile.html",
        email=email,
        docs=docs
    )


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
    users.update_one({"email": me}, {"$set": {"last_active": utcnow()}})
    return jsonify({"status": "ok"})


# ---------- Run ----------
if __name__ == "__main__":
    socketio.run(app, debug=True)
