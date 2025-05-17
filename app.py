from flask import Flask, request, jsonify, render_template, session, redirect, url_for, send_from_directory
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from flask import jsonify
from pymongo import DESCENDING
import base64
import hashlib
import os
from flask_mail import Mail, Message
from datetime import datetime
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from werkzeug.utils import secure_filename
import random


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'supersecretkey')
app.config['UPLOAD_FOLDER'] = "uploads/"
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

bcrypt = Bcrypt(app)

# MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")
db = client["messenger"]
users = db["users"]
messages = db["messages"]
original_messages = db["original_messages"]
file_messages = db["file_messages"]

SENDER_EMAIL = "gunav119147@gmail.com"
<<<<<<< HEAD
SENDER_PASSWORD = "iuhz vung lggz vzjl" 
=======
SENDER_PASSWORD = "" 
>>>>>>> 5a6eef2697ec3f93f7daa999391f9d2a8c6f7842

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'gunav119147@gmail.com'  # replace with your email
<<<<<<< HEAD
app.config['MAIL_PASSWORD'] = 'iuhz vung lggz vzjl'     # use an App Password if using Gmail
=======
app.config['MAIL_PASSWORD'] = ''     # use an App Password if using Gmail
>>>>>>> 5a6eef2697ec3f93f7daa999391f9d2a8c6f7842
mail = Mail(app)

otp_store = {}

# Generate RSA Key Pairs for Users
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return private_key, public_key

# RSA Encryption & Decryption for Messages
def encrypt_message_rsa(message, public_key_str):
    public_key = RSA.import_key(public_key_str)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher_rsa.encrypt(message.encode('utf-8'))
    return base64.b64encode(encrypted_message).decode('utf-8')

def decrypt_message_rsa(encrypted_message, private_key_str):
    private_key = RSA.import_key(private_key_str)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(base64.b64decode(encrypted_message))
    return decrypted_message.decode('utf-8')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def home():
    if "username" not in session:
        return redirect(url_for('login'))
    all_users = users.find({}, {"_id": 0, "username": 1, "profile_pic": 1})
    return render_template('home.html', current_user=session["username"], users=list(all_users))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    data = request.get_json() or request.form
    user = users.find_one({"username": data.get("username")})
    
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    if not user.get("verified", False):
        return jsonify({"message": "Please verify your email before logging in."}), 403

    if bcrypt.check_password_hash(user["password"], data.get("password")):
        session["username"] = user["username"]
        return jsonify({"message": "Login successful", "redirect": url_for('home')})
    
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('signup.html')
    
    data = request.get_json() or request.form
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if users.find_one({"username": username}):
        return jsonify({"message": "User already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    private_key, public_key = generate_rsa_keys()

    users.insert_one({
        "username": username,
        "email": email,
        "password": hashed_password,
        "verified": False,
        "public_key": public_key,
        "private_key": private_key,
        "profile_pic": "/static/default_profile.jpg"
    })

    return jsonify({"message": "User registered successfully. Please verify your email to activate login."})

# ---------- SEND OTP ----------
@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = data.get("email")
    user = users.find_one({"email": email})

    if not user:
        return jsonify({"message": "Email not found"}), 404

    if user.get("verified", False):
        return jsonify({"message": "Email already verified"}), 400

    otp = str(random.randint(100000, 999999))
    otp_store[email] = otp

    msg = Message("Your ChainVault OTP", sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f"Your OTP for verifying your ChainVault account is: {otp}"
    mail.send(msg)

    return jsonify({"message": "OTP sent to your email."})

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get("email")
    otp = data.get("otp")

    if otp_store.get(email) == otp:
        users.update_one({"email": email}, {"$set": {"verified": True}})
        otp_store.pop(email)
        return jsonify({"message": "Email verified successfully", "redirect": url_for('login')})
    else:
        return jsonify({"message": "Invalid OTP"}), 400
    
@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html')

@app.route('/verify', methods=['GET'])
def verify():
    return render_template('verify.html')

from bson.json_util import dumps

@app.route('/recent_contacts')
def recent_contacts():
    if 'username' not in session:
        return jsonify([])

    current_user = session['username']

    # Step 1: Find the most recent contact activity
    pipeline = [
        {"$match": {"$or": [
            {"sender": current_user},
            {"receiver": current_user}
        ]}},
        {"$project": {
            "contact": {
                "$cond": [
                    {"$eq": ["$sender", current_user]},
                    "$receiver",
                    "$sender"
                ]
            },
            "timestamp": 1
        }},
        {"$sort": {"timestamp": -1}},
        {"$group": {
            "_id": "$contact",
            "last_message_time": {"$first": "$timestamp"}
        }},
        {"$sort": {"last_message_time": -1}}
    ]

    recent_contacts_raw = list(messages.aggregate(pipeline))

    # Step 2: Fetch profile pictures from users collection
    contacts_data = []
    for contact in recent_contacts_raw:
        user = users.find_one({"username": contact["_id"]})
        profile_picture = user.get("profile_pic", "/static/default_profile.jpg") if user else "/static/default_profile.jpg"

        contacts_data.append({
            "_id": contact["_id"],
            "profile_picture": profile_picture
        })

    return jsonify(contacts_data)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/contacts')
def contacts():
    if "username" not in session:
        return redirect(url_for("login"))
    all_users = list(users.find({}, {"_id": 0, "username": 1, "profile_pic": 1}))
    return render_template("contacts.html", users=all_users, current_user=session["username"])

@app.route('/chat')
def chat():
    if "username" not in session:
        return redirect(url_for("login"))
    user = request.args.get("user", "Unknown")
    return render_template("chat.html", current_user=session["username"], chat_with=user)

@app.route('/send_message', methods=['POST'])
def send_message():
    if "username" not in session:
        return jsonify({"message": "Unauthorized"}), 401

    data = request.get_json()
    sender = session["username"]
    receiver = data.get("receiver")
    message = data.get("message")

    receiver_user = users.find_one({"username": receiver})
    if not receiver_user:
        return jsonify({"message": "Receiver not found"}), 404

    encrypted_message = encrypt_message_rsa(message, receiver_user["public_key"])

    # Insert encrypted message
    msg_doc = {
        "sender": sender,
        "receiver": receiver,
        "encrypted_message": encrypted_message,
        "timestamp": datetime.utcnow()
    }
    inserted = messages.insert_one(msg_doc)

    # Insert plain message linked by the message ID
    original_messages.insert_one({
        "message_id": inserted.inserted_id,
        "sender": sender,
        "original_message": message
    })

    return jsonify({"message": "Message sent successfully"})


@app.route('/get_messages', methods=['GET'])
def get_messages():
    if "username" not in session:
        return jsonify({"message": "Unauthorized"}), 401

    chat_with = request.args.get("user")
    current_user = session["username"]
    user = users.find_one({"username": current_user})
    private_key = user["private_key"]

    encrypted_messages = messages.find({
        "$or": [
            {"sender": current_user, "receiver": chat_with},
            {"sender": chat_with, "receiver": current_user}
        ]
    }).sort("timestamp", 1)

    decrypted_messages = []

    for msg in encrypted_messages:
        if msg["receiver"] == current_user:
            try:
                decrypted_message = decrypt_message_rsa(msg["encrypted_message"], private_key)
            except Exception:
                decrypted_message = "[Error decrypting message]"
        elif msg["sender"] == current_user:
            # Get original message from separate collection
            orig = original_messages.find_one({"message_id": msg["_id"]})
            decrypted_message = orig["original_message"] if orig else "[Original message not found]"

        decrypted_messages.append({
            "sender": msg["sender"],
            "message": decrypted_message,
            "timestamp": msg.get("timestamp").strftime("%Y-%m-%d %H:%M:%S") if msg.get("timestamp") else ""
        })

    return jsonify({"messages": decrypted_messages})



@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if "username" not in session:
        return redirect(url_for('login'))

    user = users.find_one({"username": session["username"]}, {"_id": 0, "password": 0, "private_key": 0})

    if request.method == 'POST':
        data = request.form
        update_data = {
            "nickname": data.get("nickname"),
            "email": data.get("email"),
            "bio": data.get("bio")
        }

        if 'profile_pic' in request.files:
            pic = request.files['profile_pic']
            if pic and pic.filename != "":
                filename = secure_filename(pic.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                pic.save(filepath)
                update_data["profile_pic"] = url_for('get_file', filename=filename)

        users.update_one({"username": session["username"]}, {"$set": update_data})
        return redirect(url_for('profile'))

    return render_template("profile.html", user=user)

@app.route('/debug/messages', methods=['GET'])
def debug_messages():
    all_messages = list(messages.find({}))
    return jsonify(all_messages)

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"message": "No file uploaded"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"message": "No selected file"}), 400
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    return jsonify({"message": "File uploaded successfully", "file_url": url_for('get_file', filename=filename)}), 200

@app.route('/send_file_message', methods=['POST'])
def send_file_message():
    if 'file' not in request.files or 'receiver' not in request.form:
        return jsonify({"error": "Missing data"}), 400

    file = request.files['file']
    receiver = request.form['receiver']
    sender = session.get("username")

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(file_path)

    file_url = url_for('get_file', filename=filename)

    file_messages.insert_one({
        "sender": sender,
        "receiver": receiver,
        "file_url": file_url,
        "filename": filename,
        "timestamp": datetime.utcnow()
    })

    return jsonify({"message": "File sent", "file_url": file_url})


@app.route("/get_file_messages")
def get_file_messages():
    user = session.get("username")
    contact = request.args.get("user")

    if not user or not contact:
        return jsonify({"error": "Missing parameters"}), 400

    history = list(file_messages.find({
        "$or": [
            {"sender": user, "receiver": contact},
            {"sender": contact, "receiver": user}
        ]
    }).sort("timestamp", 1))

    for msg in history:
        msg["_id"] = str(msg["_id"])

    return jsonify({"files": history})


@app.route("/file_chat/<contact>")
def get_file_chat(contact):
    user = session.get("user")
    history = list(file_messages.find({
        "$or": [
            {"sender": user, "receiver": contact},
            {"sender": contact, "receiver": user}
        ]
    }).sort("timestamp", 1))

    return jsonify(history)

@app.route("/uploads/<filename>")
def get_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

@app.route('/file_messenger')
def file_messenger():
    if "username" not in session:
        return redirect(url_for("login"))
    all_users = list(users.find({}, {"_id": 0, "username": 1, "profile_pic": 1}))
    return render_template("file_messenger.html", users=all_users, current_user=session["username"])

@app.route('/file_chat_ui/<contact>')
def file_chat_ui(contact):
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("file_chat.html", chat_with=contact, current_user=session["username"])



if __name__ == '__main__':
    app.run(debug=True)
