# app.py
from flask import (
    Flask, request, jsonify, render_template, redirect, url_for, session, send_file
)
from werkzeug.utils import secure_filename
from pymongo import MongoClient
import os
from threat_model import predict_threat
from datetime import datetime, timedelta
import certifi
from bson.objectid import ObjectId
from collections import Counter
import csv

# -----------------------------
# Flask setup
app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = "your_secret_key_here"

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# -----------------------------
# MongoDB setup
client = MongoClient(
    "mongodb+srv://kermeen:kermeen123@cluster0.91qw6de.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0",
    tlsCAFile=certifi.where()
)
db = client["cyberthreatDB"]
users_collection = db["users"]
history_collection = db["history"]

# -----------------------------
# Frontend Routes
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/signup")
def signup_page():
    return render_template("signup.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/user_dashboard")
def user_dashboard():
    if "username" not in session:
        return redirect(url_for("login_page"))
    return render_template("user_dashboard.html")

@app.route("/user_index")
def user_index():
    if "username" not in session:
        return redirect(url_for("login_page"))
    return render_template("user_index.html")

@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login_page"))

# -----------------------------
# Admin Dashboard
@app.route("/admin")
def admin_index():
    if "username" not in session:
        return redirect(url_for("login_page"))

    user = users_collection.find_one({"username": session["username"]})
    if not user or user.get("role") != "admin":
        return redirect(url_for("user_index"))

    return render_template("admin_index.html")

@app.route("/admin/panel")
def admin_panel():
    if "username" not in session:
        return redirect(url_for("login_page"))

    user = users_collection.find_one({"username": session["username"]})
    if not user or user.get("role") != "admin":
        return redirect(url_for("user_index"))

    users = list(users_collection.find({"role": {"$ne": "admin"}}, {"password": 0}))
    return render_template("admin_panel.html", users=users)

# -----------------------------
# Delete user
@app.route("/admin/delete_user/<user_id>", methods=["POST"])
def delete_user(user_id):
    if "username" not in session:
        return jsonify({"message": "Unauthorized"}), 401

    admin_user = users_collection.find_one({"username": session["username"]})
    if not admin_user or admin_user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 401

    try:
        users_collection.delete_one({"_id": ObjectId(user_id)})
        return jsonify({"message": "User deleted successfully"}), 200
    except Exception as e:
        return jsonify({"message": "Error deleting user", "error": str(e)}), 500

# -----------------------------
# Block/Unblock user
@app.route("/admin/block_user/<user_id>", methods=["POST"])
def block_user(user_id):
    if "username" not in session:
        return jsonify({"message": "Unauthorized"}), 401

    admin_user = users_collection.find_one({"username": session["username"]})
    if not admin_user or admin_user.get("role") != "admin":
        return jsonify({"message": "Unauthorized"}), 401

    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"message": "User not found"}), 404

        new_status = "Active" if user.get("status") == "Blocked" else "Blocked"
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"status": new_status}}
        )
        return jsonify({"message": f"User status updated to {new_status}", "new_status": new_status}), 200
    except Exception as e:
        return jsonify({"message": "Error updating user status", "error": str(e)}), 500

# -----------------------------
# Signup
@app.route("/signup", methods=["POST"])
def signup_user():
    data = request.get_json()
    if not data:
        return jsonify({"message": "Invalid request"}), 400

    email = data.get("email")
    username = data.get("username")

    if users_collection.find_one({"$or": [{"email": email}, {"username": username}]}):
        return jsonify({"message": "Email or username already exists"}), 400

    data["createdAt"] = datetime.utcnow()
    data["role"] = "user"
    data["status"] = "Active"
    users_collection.insert_one(data)
    return jsonify({"message": "Signup successful"}), 201

# -----------------------------
# Login
@app.route("/login", methods=["POST"])
def login_user():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"message": "User not found"}), 401
    if user["password"] != password:
        return jsonify({"message": "Incorrect password"}), 401

    session["username"] = username
    return jsonify({"message": "Login successful", "role": user.get("role", "user")})

# -----------------------------
# Upload + Threat Prediction
@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(file_path)

    try:
        result = predict_threat(file_path)
    except Exception as e:
        return jsonify({"error": f"Threat prediction failed: {str(e)}"}), 500

    prediction = result["label"]
    confidence = result["probability_malicious"]

    # -----------------------------
    # Save record in MongoDB 'history'
    if "username" in session:
        history_collection.insert_one({
            "username": session["username"],
            "filename": filename,
            "prediction": prediction,
            "confidence": float(confidence),
            "timestamp": datetime.utcnow()
        })

    response = {
        "filename": filename,
        "prediction": prediction,
        "confidence": confidence,
        "message": result["message"],
    }
    return jsonify(response)

# -----------------------------
# User History Page
@app.route("/history")
def user_history():
    if "username" not in session:
        return redirect(url_for("login_page"))

    username = session["username"]
    history_data = list(
        history_collection.find({"username": username}).sort("timestamp", -1)
    )

    # Convert ObjectId and datetime for template
    for item in history_data:
        item["_id"] = str(item["_id"])
        item["timestamp"] = item["timestamp"].strftime("%Y-%m-%d %H:%M:%S")

    return render_template("history.html", uploads=history_data)  # Updated variable

# -----------------------------
# User Profile
@app.route("/user_profile", methods=["GET"])
def profile():
    if "username" not in session:
        return redirect(url_for("login_page"))

    username = session["username"]
    user = users_collection.find_one({"username": username}, {"_id": 0})
    return render_template("user_profile.html", user=user)

# -----------------------------
# Update Profile
@app.route("/update_profile", methods=["POST"])
def update_profile():
    if "username" not in session:
        return jsonify({"message": "Unauthorized"}), 401

    username = session["username"]
    data = request.get_json()

    update_fields = {"fullName": data.get("fullName"), "email": data.get("email")}
    if "password" in data and data["password"].strip():
        update_fields["password"] = data["password"]

    update_fields = {k: v for k, v in update_fields.items() if v}
    users_collection.update_one({"username": username}, {"$set": update_fields})
    return jsonify({"message": "Profile updated successfully"}), 200

# -----------------------------
# Admin Analytics Dashboard
@app.route("/admin/analytics")
def admin_analytics():
    if "username" not in session:
        return redirect(url_for("login_page"))

    user = users_collection.find_one({"username": session["username"]})
    if not user or user.get("role") != "admin":
        return redirect(url_for("user_index"))

    # Fetch all history records
    total_files = history_collection.count_documents({})
    malicious_count = history_collection.count_documents({"prediction": "Malicious"})
    safe_count = history_collection.count_documents({"prediction": "Safe"})

    # Avoid division by zero
    if total_files == 0:
        safe_percentage = 0
        malicious_percentage = 0
    else:
        safe_percentage = round((safe_count / total_files) * 100, 2)
        malicious_percentage = round((malicious_count / total_files) * 100, 2)

    return render_template(
        "admin_analytics.html",
        safe_percentage=safe_percentage,
        malicious_percentage=malicious_percentage,
        total_files=total_files,
        safe_count=safe_count,
        malicious_count=malicious_count
    )

# -----------------------------
# Admin Results API
@app.route("/admin/results")
def admin_results():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user = users_collection.find_one({"username": session["username"]})
    if not user or user.get("role") != "admin":
        return jsonify({"error": "Forbidden"}), 403

    total_files = history_collection.count_documents({})
    malicious_count = history_collection.count_documents({"prediction": "Malicious"})
    safe_count = history_collection.count_documents({"prediction": "Safe"})

    return jsonify({
        "stats": {
            "Safe": safe_count,
            "Malicious": malicious_count
        },
        "total_files": total_files
    })

# -----------------------------
# New Analytics API for multiple charts
@app.route("/admin/analytics_data")
def admin_analytics_data():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user = users_collection.find_one({"username": session["username"]})
    if not user or user.get("role") != "admin":
        return jsonify({"error": "Forbidden"}), 403

    # Safe vs Malicious
    safe_count = history_collection.count_documents({"prediction": "Safe"})
    malicious_count = history_collection.count_documents({"prediction": "Malicious"})

    # Files per user
    user_counts = Counter()
    for doc in history_collection.find({}, {"username": 1}):
        user_counts[doc["username"]] += 1

    # Recent uploads over last 30 days
    recent_uploads = Counter()
    cutoff = datetime.utcnow() - timedelta(days=30)
    for doc in history_collection.find({"timestamp": {"$gte": cutoff}}, {"timestamp": 1}):
        ts = doc["timestamp"]
        if isinstance(ts, datetime):
            date_str = ts.strftime("%Y-%m-%d")
            recent_uploads[date_str] += 1

    return jsonify({
        "safe_vs_malicious": {"Safe": safe_count, "Malicious": malicious_count},
        "files_per_user": dict(user_counts),
        "recent_uploads": dict(sorted(recent_uploads.items()))
    })


# -----------------------------
# Download analysis report for a specific file
@app.route("/download_report/<filename>", methods=["GET"])
def download_report(filename):
    if "username" not in session:
        return redirect(url_for("login_page"))

    username = session["username"]

    # Fetch record from MongoDB
    record = history_collection.find_one({"username": username, "filename": filename})
    if not record:
        return "Report not found", 404

    # Prepare report CSV
    report_filename = f"{filename}_report.csv"
    report_path = os.path.join(app.config["UPLOAD_FOLDER"], report_filename)

    with open(report_path, mode="w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Username", "Filename", "Prediction", "Confidence", "Timestamp"])
        writer.writerow([
            record["username"],
            record["filename"],
            record["prediction"],
            f"{record['confidence']:.2f}%",
            record["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        ])

    return send_file(report_path, as_attachment=True)

# -----------------------------
# Run the app
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
