from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from pymongo import MongoClient
from bson.objectid import ObjectId
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = "your_secret_key"

# MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["messenger"]
users_col = db["users"]
file_messages_col = db["file_messages"]

# File upload path
UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Dummy login (replace with your login logic)
@app.before_request
def fake_login():
    session['user_id'] = "6615187cf4a5e82e4087d111"  # your logged-in user ID as string
    session['username'] = "current_user"

# File Messenger Page
@app.route('/file_messanger')
def file_messanger():
    current_user_id = session['user_id']
    all_users = users_col.find({"_id": {"$ne": ObjectId(current_user_id)}})
    return render_template("file_messanger.html", users=all_users)

# File Chat Page
@app.route('/file_chat/<contact_id>', methods=['GET', 'POST'])
def file_chat(contact_id):
    current_user_id = session['user_id']
    current_user = users_col.find_one({"_id": ObjectId(current_user_id)})
    contact_user = users_col.find_one({"_id": ObjectId(contact_id)})

    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file:
            filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{uploaded_file.filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            uploaded_file.save(filepath)

            file_messages_col.insert_one({
                "sender_id": ObjectId(current_user_id),
                "receiver_id": ObjectId(contact_id),
                "filename": uploaded_file.filename,
                "filepath": filepath,
                "timestamp": datetime.utcnow()
            })

            return redirect(url_for('file_chat', contact_id=contact_id))

    # Fetch messages between the users
    messages = file_messages_col.find({
        "$or": [
            {"sender_id": ObjectId(current_user_id), "receiver_id": ObjectId(contact_id)},
            {"sender_id": ObjectId(contact_id), "receiver_id": ObjectId(current_user_id)},
        ]
    }).sort("timestamp", 1)

    return render_template("file_chat.html", messages=messages, contact=contact_user, current_user=current_user)

# File download
@app.route('/download/<path:filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
