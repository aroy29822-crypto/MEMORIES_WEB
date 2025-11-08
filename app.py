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

ADMIN_EMAIL = "aroy29822@gmail.com"


@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("feed"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].lower()
        password = request.form["password"]
        user = users.find_one({"email":email})
        if user and check_password_hash(user["password"], password):
            session["user"] = email
            return redirect(url_for("feed"))
        flash("Invalid credentials")
    return render_template("login.html")


@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        email = request.form["email"].lower()
        password = request.form["password"]

        if users.find_one({"email":email}):
            flash("Already registered")
            return redirect(url_for("register"))

        users.insert_one({
            "email":email,
            "password":generate_password_hash(password)
        })
        flash("Registered. Now Login.")
        return redirect(url_for("login"))
    return render_template("login.html")
@app.route("/logout")
def logout():
    session.pop("user",None)
    return redirect(url_for("login"))


@app.route("/upload", methods=["GET","POST"])
def upload():
    if "user" not in session: return redirect(url_for("login"))

    if request.method=="POST":
        file = request.files.get("file")
        place = request.form.get("place","")
        date  = request.form.get("date","")
        desc  = request.form.get("desc","")

        if not file or file.filename=="": 
            flash("Select a file")
            return redirect(url_for("upload"))

        ext = file.filename.rsplit(".",1)[-1].lower()
        if ext not in ALLOWED_EXT:
            flash("File type not allowed")
            return redirect(url_for("upload"))

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

        flash("Uploaded")
        return redirect(url_for("feed"))

    return render_template("upload.html")


@app.route("/feed")
def feed():
    if "user" not in session: return redirect(url_for("login"))
    docs = list(posts.find().sort("time",-1))
    return render_template("feed.html", docs=docs)


@app.route("/profile")
def profile():
    if "user" not in session: return redirect(url_for("login"))
    me = session["user"]
    docs = list(posts.find({"owner":me}).sort("time",-1))
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

    if doc['owner'] != me and me != ADMIN_EMAIL:
        flash("No permission to edit")
        return redirect(url_for('feed'))

    if request.method == 'POST':
        posts.update_one(
            {"_id": doc["_id"]},
            {"$set": {
                "desc": request.form['desc'],
                "place":request.form['place'],
                "date":request.form['date']
            }}
        )
        flash("Updated")
        return redirect(url_for('admin') if me==ADMIN_EMAIL else url_for('profile'))   

    return render_template("edit.html", doc=doc)


@app.route("/admin")
def admin():
    if "user" not in session: return redirect(url_for("login"))
    if session["user"] != ADMIN_EMAIL:
        flash("Admin only")
        return redirect(url_for("feed"))
    docs = list(posts.find().sort("time",-1))
    return render_template("admin.html", docs=docs)


@app.post('/delete/<id>')
def delete_post(id):
    if 'user' not in session or session['user'] != ADMIN_EMAIL:
        flash("Admin only")
        return redirect(url_for('feed'))
    posts.delete_one({"_id": ObjectId(id)})
    flash("Post deleted.")
    return redirect(url_for('admin'))


@app.post('/feedback')
def feedback():
    if "user" not in session:
        return redirect(url_for("login"))
    msg = request.form.get("msg","")
    if msg.strip():
        feedbacks.insert_one({
            "user": session["user"],
            "msg": msg,
            "time": datetime.utcnow()
        })
    flash("Thanks for your feedback 💗")
    return redirect(url_for('feed'))


@app.context_processor
def inject_admin():
    return dict(ADMIN_EMAIL=ADMIN_EMAIL)


@app.route("/admin/feedbacks")
def admin_feedback():
    if "user" not in session: return redirect(url_for('login'))
    if session["user"] != ADMIN_EMAIL:
        flash("not admin")
        return redirect(url_for('feed'))
    
    docs = list(feedbacks.find().sort("time",-1))
    return render_template("feedback_admin.html", docs=docs)


if __name__ == "__main__":
    app.run(debug=True)
