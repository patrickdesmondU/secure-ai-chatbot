"""
Secure AI Chatbot - Flask Application (Groq Edition)
Uses Groq API with Llama 3.3 70B - free tier, no credit card needed
"""

import os
import sqlite3
from datetime import timedelta
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash
from groq import Groq

# Load environment variables
load_dotenv()

# Configuration
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
FLASK_ENV = os.getenv("FLASK_ENV", "development")

if not GROQ_API_KEY:
    raise ValueError("GROQ_API_KEY not found in environment variables. Get one at https://console.groq.com/keys")
if not FLASK_SECRET_KEY:
    raise ValueError("FLASK_SECRET_KEY not found in environment variables")

# Initialize Flask app
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# Session configuration
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=1)

# Initialize Groq client
groq_client = Groq(api_key=GROQ_API_KEY)
MODEL_NAME = "llama-3.3-70b-versatile"  # Fast, capable, free tier friendly

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

DATABASE = "chatbot.db"


def get_db():
    """Get a database connection with auto-close context manager."""
    conn = sqlite3.connect(DATABASE, timeout=20.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


class DBConnection:
    """Context manager that guarantees connection closure."""
    def __enter__(self):
        self.conn = sqlite3.connect(DATABASE, timeout=20.0)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            self.conn.close()
        return False


def init_db():
    with open("schema.sql", "r") as f:
        schema = f.read()
    conn = get_db()
    conn.executescript(schema)
    conn.commit()
    conn.close()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    password_hash = generate_password_hash(password)

    try:
        with DBConnection() as conn:
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
            conn.commit()
            user_id = cursor.lastrowid

        session.permanent = True
        session["user_id"] = user_id
        session["username"] = username

        return jsonify({"message": "User registered successfully", "user_id": user_id}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    with DBConnection() as conn:
        user = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    if user and check_password_hash(user["password_hash"], password):
        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return jsonify({"message": "Login successful", "username": user["username"]}), 200

    return jsonify({"error": "Invalid username or password"}), 401


@app.route("/api/auth/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200


@app.route("/api/auth/me", methods=["GET"])
@login_required
def get_current_user():
    return jsonify({"user_id": session["user_id"], "username": session["username"]}), 200


@app.route("/api/chat", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def chat():
    data = request.get_json()
    message = data.get("message", "").strip()
    user_id = session["user_id"]

    if not message:
        return jsonify({"error": "Message is required"}), 400
    if len(message) > 2000:
        return jsonify({"error": "Message exceeds 2000 character limit"}), 400

    # Store user message and get history
    with DBConnection() as conn:
        conn.execute(
            "INSERT INTO conversations (user_id, role, content) VALUES (?, ?, ?)",
            (user_id, "user", message)
        )
        conn.commit()

        history = conn.execute(
            "SELECT role, content FROM conversations WHERE user_id = ? ORDER BY created_at DESC LIMIT 10",
            (user_id,)
        ).fetchall()

    # Build messages for Groq (OpenAI-compatible format)
    messages = [
        {"role": "system", "content": "You are a helpful assistant. Keep responses concise, 3-4 sentences maximum."}
    ]
    for row in reversed(history):
        messages.append({"role": row["role"], "content": row["content"]})

    try:
        response = groq_client.chat.completions.create(
            model=MODEL_NAME,
            messages=messages,
            max_tokens=200,
            temperature=0.7,
        )
        ai_message = response.choices[0].message.content

        # Store AI response
        with DBConnection() as conn:
            conn.execute(
                "INSERT INTO conversations (user_id, role, content) VALUES (?, ?, ?)",
                (user_id, "assistant", ai_message)
            )
            conn.commit()

        return jsonify({"response": ai_message}), 200
    except Exception as e:
        return jsonify({"error": "Failed to get AI response", "details": str(e)}), 500


@app.route("/api/history", methods=["GET"])
@login_required
def get_history():
    user_id = session["user_id"]
    with DBConnection() as conn:
        messages = conn.execute(
            "SELECT role, content, created_at FROM conversations WHERE user_id = ? ORDER BY created_at ASC",
            (user_id,)
        ).fetchall()

    return jsonify({
        "messages": [
            {"role": row["role"], "content": row["content"], "timestamp": row["created_at"]}
            for row in messages
        ]
    }), 200


@app.route("/api/history", methods=["DELETE"])
@login_required
def clear_history():
    user_id = session["user_id"]
    with DBConnection() as conn:
        conn.execute("DELETE FROM conversations WHERE user_id = ?", (user_id,))
        conn.commit()
    return jsonify({"message": "Conversation history cleared"}), 200


@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "model": MODEL_NAME}), 200


if __name__ == "__main__":
    if not os.path.exists(DATABASE):
        init_db()
    app.run(host="0.0.0.0", port=5000, debug=(FLASK_ENV == "development"))