import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from datetime import datetime
from bson import ObjectId
from dotenv import load_dotenv
import cloudinary
import cloudinary.uploader

load_dotenv()

ALLOWED_EXT = {'png','jpg','jpeg','gif','mp4','mov','avi','mkv','webm'}

cloudinary.config(
    cloud_name=os.getenv("CLOUD_NAME"),
    api_key=os.getenv("CLOUD_API_KEY"),
    api_secret=os.getenv("CLOUD_API_SECRET")
)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "secret")

MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["memories_db"]
users = db["users"]
posts = db["posts"]
feedbacks = db['feedbacks']
login_logs = db['login_logs']
logs = db['logs']  # NEW: audit logs

ADMIN_EMAIL = "aroy29822@gmail.com"
import random

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


# ---------- logging helper ----------
def log_action(user_email, action, details=None):
    try:
        logs.insert_one({
            "user": user_email,
            "action": action,
            "details": details or {},
            "time": datetime.utcnow()
        })
    except Exception:
        # do not break the app if logging fails
        pass


# ---------- context ----------
@app.context_processor
def inject_admin():
    return dict(ADMIN_EMAIL=ADMIN_EMAIL)


# ---------- routes ----------
@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("feed"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET","POST"])
def login():
    msg = ""
    QUOTES = [
        "Welcome back!",
        "Nice to see you again 🤝",
        "Today is your day!",
        "Happiness looks good on you!",
        "You’re one step closer than yesterday!",
    ]

    if request.method == "POST":
        email = request.form["email"].lower()
        password = request.form["password"]
        user = users.find_one({"email":email})
        
        if user and check_password_hash(user["password"], password):
            session["user"] = email
            session["just_logged"] = True  # <--- ADD THIS
            return redirect(url_for("feed"))

            import random
            msg = random.choice(QUOTES)

            # show animation + auto redirect to feed
            return render_template("login.html", message=msg, go_feed=True)

        flash("Invalid credentials")
    return render_template("login.html", message=msg, go_feed=False)


@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        first = request.form.get("first","").strip()
        last  = request.form.get("last","").strip()
        email = request.form.get("email","").lower()
        password = request.form.get("password","")

        if users.find_one({"email": email}):
            flash("Already registered")
            return redirect(url_for("register"))

        users.insert_one({
            "first_name": first,
            "last_name": last,
            "email": email,
            "password": generate_password_hash(password),
            "created_at": datetime.utcnow(),
            "last_login": None
        })

        flash("Registered successfully. Now Login.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/logout")
def logout():
    e = session.get("user")
    session.pop("user", None)
    if e:
        log_action(e, "logout")
    return redirect(url_for("login"))


@app.route("/upload", methods=["GET","POST"])
def upload():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("file")
        place = request.form.get("place","").strip()
        date  = request.form.get("date","").strip()
        desc  = request.form.get("desc","").strip()

        if not file or file.filename == "":
            flash("Select a file")
            return redirect(url_for("upload"))

        ext = file.filename.rsplit(".",1)[-1].lower()
        if ext not in ALLOWED_EXT:
            flash("File type not allowed")
            return redirect(url_for("upload"))

        # 100 MB size limit
        raw = file.read()
        if len(raw) > 100 * 1024 * 1024:
            flash("File too large (Max 100 MB)")
            return redirect(url_for("upload"))
        file.seek(0)

        up = cloudinary.uploader.upload(file, resource_type="auto")
        url = up["secure_url"]

        posts.insert_one({
            "owner": session["user"],
            "url": url,
            "place": place,
            "date": date,
            "desc": desc,
            "time": datetime.utcnow()
        })

        log_action(session["user"], "upload", {"url": url, "place": place})
        flash("Uploaded")
        return redirect(url_for("feed"))

    return render_template("upload.html")

@app.route("/feed")
def feed():
    if "user" not in session: 
        return redirect(url_for("login"))

    me = session["user"]
    user = users.find_one({"email":me})
    docs = list(posts.find().sort("time",-1))

    firstname = user.get("first_name","Friend")

    # pick random quote
    quote = random.choice(QUOTES)

    # remove flag so popup shows only 1 time after login
    show_popup = session.pop("just_logged", None)

    return render_template("feed.html", docs=docs, firstname=firstname, quote=quote, show_popup=show_popup)


@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect(url_for("login"))
    me = session["user"]
    docs = list(posts.find({"owner": me}).sort("time", -1))
    return render_template("profile.html", me=me, docs=docs)


@app.route('/edit/<id>', methods=['GET','POST'])
def edit_post(id):
    if 'user' not in session:
        return redirect(url_for('login'))

    me = session['user']
    doc = posts.find_one({"_id": ObjectId(id)})
    if not doc:
        flash("Not found")
        return redirect(url_for('feed'))

    # owner or admin only
    if doc['owner'] != me and me != ADMIN_EMAIL:
        flash("No permission to edit")
        return redirect(url_for('feed'))

    if request.method == 'POST':
        new_desc  = request.form.get('desc','').strip()
        new_place = request.form.get('place','').strip()
        new_date  = request.form.get('date','').strip()

        posts.update_one(
            {"_id": doc["_id"]},
            {"$set": {"desc": new_desc, "place": new_place, "date": new_date}}
        )
        log_action(me, "edit", {"post_id": str(doc["_id"])})
        flash("Updated")
        return redirect(url_for('admin') if me == ADMIN_EMAIL else url_for('profile'))

    return render_template("edit.html", doc=doc)


# ----- classic admin (posts grid) -----
@app.route("/admin")
def admin():
    if "user" not in session:
        return redirect(url_for("login"))
    if session["user"] != ADMIN_EMAIL:
        flash("Admin only")
        return redirect(url_for("feed"))
    docs = list(posts.find().sort("time", -1))
    return render_template("admin.html", docs=docs)


@app.post('/delete/<id>')
def delete_post(id):
    if 'user' not in session or session['user'] != ADMIN_EMAIL:
        flash("Admin only")
        return redirect(url_for('feed'))
    posts.delete_one({"_id": ObjectId(id)})
    log_action(session["user"], "delete", {"post_id": id})
    flash("Post deleted.")
    return redirect(url_for('admin'))


# ----- feedback (from feed page) -----
@app.post('/feedback')
def feedback():
    if "user" not in session:
        return redirect(url_for("login"))
    msg = request.form.get("msg","").strip()
    if msg:
        feedbacks.insert_one({
            "user": session["user"],
            "msg": msg,
            "time": datetime.utcnow()
        })
        log_action(session["user"], "feedback")
    flash("Thanks for your lovely feedback 💗")
    return redirect(url_for('feed'))


# ----- admin: feedback viewer -----
@app.route("/admin/feedbacks")
def admin_feedback():
    if "user" not in session:
        return redirect(url_for('login'))
    if session["user"] != ADMIN_EMAIL:
        flash("not admin")
        return redirect(url_for('feed'))
    
    docs = list(feedbacks.find().sort("time",-1))
    return render_template("feedback_admin.html", docs=docs)


# ----- NEW: admin overview (users + logs dashboard) -----
@app.route("/admin/overview")
def admin_overview():
    if "user" not in session:
        return redirect(url_for("login"))
    if session["user"] != ADMIN_EMAIL:
        flash("Admin only")
        return redirect(url_for("feed"))

    users_list = list(users.find({}, {"password": 0}).sort("created_at", -1))
    recent_logs = list(logs.find().sort("time", -1).limit(200))
    total_users = users.count_documents({})
    total_posts = posts.count_documents({})

    return render_template("admin_overview.html",
                           users=users_list,
                           logs=recent_logs,
                           total_users=total_users,
                           total_posts=total_posts)


# ----- NEW: admin reset password for a user -----
@app.route("/admin/reset_password/<email>", methods=["GET","POST"])
def admin_reset_password(email):
    if "user" not in session or session["user"] != ADMIN_EMAIL:
        flash("Admin only")
        return redirect(url_for("feed"))

    u = users.find_one({"email": email})
    if not u:
        flash("User not found.")
        return redirect(url_for("admin_overview"))

    if request.method == "POST":
        newpw = request.form.get("password","").strip()
        if not newpw:
            flash("Provide a password")
            return redirect(url_for("admin_reset_password", email=email))
        users.update_one({"email": email}, {"$set": {"password": generate_password_hash(newpw)}})
        log_action(session['user'], "reset_password", {"for": email})
        flash("Password reset for " + email)
        return redirect(url_for("admin_overview"))

    return render_template("admin_reset_password.html", user_email=email)


# ----- NEW: admin view any user's profile -----
@app.route("/admin/user/<email>")
def admin_user_profile(email):
    if "user" not in session or session["user"] != ADMIN_EMAIL:
        flash("Admin only")
        return redirect(url_for("feed"))
    docs = list(posts.find({"owner": email}).sort("time", -1))
    return render_template("admin_user_profile.html", docs=docs, user_email=email)
@app.route("/admin/loginlogs")
def admin_loginlogs():
    if "user" not in session: return redirect(url_for('login'))
    if session["user"] != ADMIN_EMAIL:
        flash("Admin only")
        return redirect(url_for('feed'))

    logs = list(login_logs.find().sort("time",-1))
    return render_template("admin_loginlogs.html", logs=logs)

@app.route("/admin/users")
def admin_users():
    if "user" not in session: return redirect(url_for('login'))
    if session["user"] != ADMIN_EMAIL:
        flash("Admin only")
        return redirect(url_for('feed'))

    all_users = list(users.find().sort("created_at",-1))
    return render_template("admin_users.html", users=all_users)


if __name__ == "__main__":
    app.run(debug=True)
