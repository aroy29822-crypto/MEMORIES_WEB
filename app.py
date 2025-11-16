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

load_dotenv()

# ---------- Flask and Mongo setup ----------
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "secret")

MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["memories_db"]
users = db["users"]
posts = db["posts"]
feedbacks = db["feedbacks"]
login_logs = db["login_logs"]
logs = db["logs"]  # audit logs

# ---------- Cloudinary setup ----------
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi', 'mkv', 'webm'}
cloudinary.config(
    cloud_name=os.getenv("CLOUD_NAME"),
    api_key=os.getenv("CLOUD_API_KEY"),
    api_secret=os.getenv("CLOUD_API_SECRET")
)

ADMIN_EMAIL = "aroy29822@gmail.com"

QUOTES = [
    "Memories are little time capsules we can open anytime.",
    "Good days become good memories.",
    "Every moment turns into a story one day.",
    "We didn’t realize we were making memories, we just knew we were having fun.",
    "Photos are the proof that we lived that second.",
    "Some moments are too beautiful for words.",
    "Time passes, memories stay.",
    "Life moves fast, but memories freeze the best parts.",
    "Some memories never fade, they glow.",
    "Friends make ordinary days unforgettable."
]


# ---------- Helpers ----------
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
    safe_routes = ["login", "register", "static", "check_status"]
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
def inject_admin():
    return dict(ADMIN_EMAIL=ADMIN_EMAIL)


# ---------- Routes ----------
@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("feed"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        email = request.form["email"].lower()
        password = request.form["password"]
        user = users.find_one({"email": email})

        if not user:
            flash("No such user found.")
            return redirect(url_for("login"))

        if user.get("blocked"):
            flash("Your account has been blocked by Admin.")
            return redirect(url_for("login"))

        if user and check_password_hash(user["password"], password):
            session["user"] = email
            session["just_logged"] = True
            users.update_one({"email": email}, {"$set": {"last_login": datetime.utcnow()}})
            login_logs.insert_one({"user": email, "time": datetime.utcnow(), "action": "login"})
            if email == ADMIN_EMAIL:
                return redirect(url_for("admin_overview"))
            return redirect(url_for("feed"))
        else:
            flash("Wrong password.")
            return redirect(url_for("login"))

    return render_template("login.html", message=msg)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first = request.form.get("first", "").strip()
        last = request.form.get("last", "").strip()
        email = request.form.get("email", "").lower()
        password = request.form.get("password", "")

        if users.find_one({"email": email}):
            flash("Already registered.")
            return redirect(url_for("register"))

        users.insert_one({
            "first_name": first,
            "last_name": last,
            "email": email,
            "password": generate_password_hash(password),
            "created_at": datetime.utcnow(),
            "last_login": None
        })
        flash("Registered successfully. Now login.")
        return redirect(url_for("login"))
    return render_template("register.html")


# ----- Admin block/unblock -----
@app.post("/admin/block/<email>")
def admin_block_user(email):
    if "user" not in session or session["user"].lower() != ADMIN_EMAIL:
        flash("Admin only.")
        return redirect(url_for("feed"))
    users.update_one({"email": email.lower()}, {"$set": {"blocked": True}})
    log_action(session["user"], "block_user", {"email": email})
    flash(f"{email} blocked successfully.")
    return redirect(url_for("admin_users"))


@app.post("/admin/unblock/<email>")
def admin_unblock_user(email):
    if "user" not in session or session["user"].lower() != ADMIN_EMAIL:
        flash("Admin only.")
        return redirect(url_for("feed"))
    users.update_one({"email": email.lower()}, {"$set": {"blocked": False}})
    log_action(session["user"], "unblock_user", {"email": email})
    flash(f"{email} unblocked successfully.")
    return redirect(url_for("admin_users"))


@app.route("/logout")
def logout():
    e = session.get("user")
    session.pop("user", None)
    if e:
        log_action(e, "logout")
        try:
            login_logs.insert_one({"user": e, "time": datetime.utcnow(), "action": "logout"})
        except Exception:
            pass
    return redirect(url_for("login"))

@app.route("/admin/reset_password/<email>", methods=["GET", "POST"])
def admin_reset_password(email):
    if "user" not in session or session["user"].lower() != ADMIN_EMAIL:
        flash("Admin only.")
        return redirect(url_for("login"))

    user = users.find_one({"email": email})
    if not user:
        flash("User not found.")
        return redirect(url_for("admin_users"))

    if request.method == "POST":
        new_pass = request.form.get("new_password", "").strip()
        if len(new_pass) < 5:
            flash("Password must be at least 5 characters.")
            return redirect(request.url)

        users.update_one({"email": email}, {
            "$set": {"password": generate_password_hash(new_pass)}
        })
        
        flash(f"Password reset successfully for {email}")
        return redirect(url_for("admin_users"))

    return render_template("admin_reset_password.html", email=email)

# ---------- Upload ----------
@app.route("/upload", methods=["GET", "POST"])
@require_active_user
def upload():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
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

    return render_template("upload.html")


# ---------- Feed ----------
@app.route("/feed")
@require_active_user
def feed():
    if "user" not in session:
        return redirect(url_for("login"))
    me = session["user"].lower()
    user = users.find_one({"email": me})
    docs = list(posts.find().sort("time", 1))
    firstname = (user or {}).get("first_name", "Friend")
    quote = random.choice(QUOTES)
    show_popup = session.pop("just_logged", None)
    return render_template("feed.html", docs=docs, firstname=firstname, quote=quote, show_popup=show_popup)


# ---------- Profile ----------
@app.route("/profile")
@require_active_user
def profile():
    if "user" not in session:
        return redirect(url_for("login"))
    me = session["user"].lower()
    docs = list(posts.find({"owner": me}).sort("time", -1))
    return render_template("profile.html", me=me, docs=docs)


# ---------- Edit ----------
@app.route("/edit/<id>", methods=["GET", "POST"])
def edit_post(id):
    if "user" not in session:
        return redirect(url_for("login"))
    me = session["user"].lower()
    doc = posts.find_one({"_id": ObjectId(id)})
    if not doc:
        flash("Post not found.")
        return redirect(url_for("feed"))
    if doc.get("owner") != me and me != ADMIN_EMAIL:
        flash("No permission.")
        return redirect(url_for("feed"))
    if request.method == "POST":
        new_desc = request.form.get("desc", "").strip()
        new_place = request.form.get("place", "").strip()
        new_date = request.form.get("date", "").strip()
        posts.update_one({"_id": doc["_id"]}, {"$set": {"desc": new_desc, "place": new_place, "date": new_date}})
        flash("Updated successfully.")
        return redirect(url_for("admin") if me == ADMIN_EMAIL else url_for("profile"))
    return render_template("edit.html", doc=doc)

# ---------- Admin Delete Post ----------
@app.post("/delete/<id>")
def delete_post(id):
    if "user" not in session or session["user"].lower() != ADMIN_EMAIL:
        flash("Admin only.")
        return redirect(url_for("feed"))

    try:
        posts.delete_one({"_id": ObjectId(id)})
        flash("Post deleted successfully.")
    except Exception:
        flash("Failed to delete.")

    return redirect(url_for("admin"))

# ---------- Admin: Overview ----------
@app.route("/admin/overview")
def admin_overview():
    if "user" not in session or session["user"].lower() != ADMIN_EMAIL:
        return redirect(url_for("login"))
    users_list = list(users.find({}, {"password": 0}).sort("created_at", -1))
    recent_logs = list(logs.find().sort("time", -1).limit(200))
    total_users = users.count_documents({})
    total_posts = posts.count_documents({})
    return render_template("admin_overview.html",
                           users=users_list,
                           logs=recent_logs,
                           total_users=total_users,
                           total_posts=total_posts)

# ---------- Admin: All Posts (Classic Admin Page) ----------
@app.route("/admin")
def admin():
    if "user" not in session:
        return redirect(url_for("login"))
    if session["user"].lower() != ADMIN_EMAIL:
        flash("Admin only")
        return redirect(url_for("feed"))

    docs = list(posts.find().sort("time", -1))
    return render_template("admin.html", docs=docs)

@app.route("/admin/live")
def admin_live():
    if "user" not in session or session["user"].lower() != ADMIN_EMAIL:
        return redirect(url_for("login"))
    return render_template("admin_live.html")


# ---------- Admin: Live Stats ----------

"""@app.route("/admin/live_stats")
def admin_live_stats():
    if "user" not in session or session["user"].lower() != ADMIN_EMAIL:
        return jsonify({"error": "unauthorized"}), 403

    total_users = users.count_documents({})
    total_posts = posts.count_documents({})
    total_feedback = feedbacks.count_documents({})

    # all users for online status
    all_users = list(users.find({}, {"email": 1, "last_active": 1, "_id": 0}))

    threshold_time = datetime.utcnow().timestamp() - 5
    online_users = [u["email"] for u in all_users if u.get("last_active") and u["last_active"].timestamp() >= threshold_time]

    # Convert recent logins
    recent_logins_raw = list(login_logs.find().sort("time", -1).limit(10))
    recent_logins = [
        {
            "user": x["user"],
            "action": x.get("action", ""),
            "time": x["time"].strftime("%H:%M:%S %d-%b")
        }
        for x in recent_logins_raw
    ]

    # Convert recent uploads
    recent_uploads_raw = list(posts.find().sort("time", -1).limit(5))
    recent_uploads = [
        {
            "owner": x["owner"],
            "time": x["time"].strftime("%H:%M:%S %d-%b")
        }
        for x in recent_uploads_raw
    ]

    for u in all_users:
        if u.get("last_active"):
            u["last_active"] = u["last_active"].isoformat()

    return jsonify({
        "total_users": total_users,
        "total_posts": total_posts,
        "total_feedback": total_feedback,
        "online_users": online_users,
        "recent_logins": recent_logins,
        "recent_uploads": recent_uploads,
        "all_users": all_users
    })"""


@app.route("/heartbeat")
def heartbeat():
    """Tracks user online activity every few seconds."""
    if "user" not in session:
        return jsonify({"status": "no_session"})

    me = session["user"].lower()
    users.update_one({"email": me}, {"$set": {"last_active": datetime.utcnow()}})
    return jsonify({"status": "ok"})

# ---------- NEW: Admin Live User JSON ----------
@app.route("/admin/live_users_json")
def admin_live_users_json():
    if "user" not in session or session["user"].lower() != ADMIN_EMAIL:
        return jsonify({"error": "unauthorized"}), 403
    threshold = datetime.utcnow() - timedelta(minutes=3)
    all_users = list(users.find({}, {"email": 1, "last_active": 1, "blocked": 1}))
    live_data = []
    for u in all_users:
        is_online = bool(u.get("last_active") and u["last_active"] >= threshold)
        live_data.append({
            "email": u["email"],
            "is_online": is_online,
            "blocked": u.get("blocked", False)
        })
    return jsonify(live_data)
# ---------- Admin: Feedback Viewer ----------
@app.route("/admin/feedbacks")
def admin_feedback():
    if "user" not in session:
        return redirect(url_for('login'))
    if session["user"].lower() != ADMIN_EMAIL:
        flash("Admin only")
        return redirect(url_for('feed'))

    docs = list(feedbacks.find().sort("time", -1))
    return render_template("feedback_admin.html", docs=docs)


# ---------- Admin: Users Page ----------
@app.route("/admin/users")
def admin_users():
    if "user" not in session:
        return redirect(url_for("login"))
    if session["user"].lower() != ADMIN_EMAIL:
        flash("Admin only.")
        return redirect(url_for("feed"))
    all_users = list(users.find().sort("created_at", -1))
    threshold = datetime.utcnow() - timedelta(minutes=3)
    for u in all_users:
        last_active = u.get("last_active")
        u["is_online"] = bool(last_active and last_active >= threshold)
    return render_template("admin_users.html", users=all_users)

# ---------- Admin: View Specific User Profile ----------
@app.route("/admin/user/<email>")
def admin_user_profile(email):
    if "user" not in session:
        return redirect(url_for("login"))
    if session["user"].lower() != ADMIN_EMAIL:
        flash("Admin only")
        return redirect(url_for("feed"))

    docs = list(posts.find({"owner": email.lower()}).sort("time", -1))
    user = users.find_one({"email": email.lower()})
    return render_template("admin_user_profile.html", docs=docs, user_email=email.lower(), user=user)

# ---------- App Runner ----------
if __name__ == "__main__":
    app.run(debug=True)