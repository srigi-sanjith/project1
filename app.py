import os
import smtplib
import ssl
import secrets
import time
import hashlib
from email.message import EmailMessage
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from dotenv import load_dotenv
from email_validator import validate_email, EmailNotValidError
import bcrypt

load_dotenv()

app = Flask(__name__, static_folder="static")
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
FROM_EMAIL = os.getenv("FROM_EMAIL", SMTP_USER)
OTP_EXPIRY_SECONDS = int(os.getenv("OTP_EXPIRY_SECONDS", 300)) 
MAX_OTPS_PER_HOUR = int(os.getenv("MAX_OTPS_PER_HOUR", 5))
MAX_VERIFY_ATTEMPTS = int(os.getenv("MAX_VERIFY_ATTEMPTS", 5))

otp_store = {}     
send_counters = {} 

def rate_limit_send(key: str):
    """Simple sliding-window per-key limiter for OTP sends."""
    now = time.time()
    window = 3600  
    arr = send_counters.get(key, [])
    arr = [t for t in arr if now - t < window]
    if len(arr) >= MAX_OTPS_PER_HOUR:
        return False
    arr.append(now)
    send_counters[key] = arr
    return True

def hash_otp(otp: str, salt: bytes = None):
    """Hash OTP using bcrypt for secure storage."""
    if salt is None:
        salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(otp.encode('utf-8'), salt)
    return hashed

def verify_otp_hash(otp: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(otp.encode('utf-8'), hashed)
    except Exception:
        return False

def send_email_otp(to_email: str, otp: str):
    """Send OTP via SMTP. Uses TLS (STARTTLS)."""
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        raise RuntimeError("SMTP not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASS env variables.")

    msg = EmailMessage()
    msg['Subject'] = 'Your One-Time Password (OTP)'
    msg['From'] = FROM_EMAIL
    msg['To'] = to_email
    msg.set_content(f"Your OTP is: {otp}\nThis code will expire in {OTP_EXPIRY_SECONDS//60} minutes.\nIf you did not request this, ignore this email.")

    context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            if SMTP_PORT == 587:
                server.starttls(context=context)
                server.ehlo()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)

def require_session(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'key' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/request-otp", methods=["POST"])
def request_otp():
    """User submits email or phone (we'll assume email here)."""
    identifier = request.form.get("identifier", "").strip()
    medium = request.form.get("medium", "email")
    if not identifier:
        flash("Please provide your email or phone.", "danger")
        return redirect(url_for("index"))

    if medium == "email":
        try:
            v = validate_email(identifier)
            identifier = v.email
        except EmailNotValidError as e:
            flash("Invalid email address.", "danger")
            return redirect(url_for("index"))

    if not rate_limit_send(identifier):
        flash("Too many OTP requests. Try again later.", "danger")
        return redirect(url_for("index"))
    
    otp = f"{secrets.randbelow(10**6):06d}"
    hashed = hash_otp(otp)
    expiry_ts = time.time() + OTP_EXPIRY_SECONDS
    otp_store[identifier] = {
        "hash": hashed,
        "expiry": expiry_ts,
        "attempts": 0,
        "created_at": time.time()
    }

    try:
        if medium == "email":
            send_email_otp(identifier, otp)
        else:
            raise RuntimeError("SMS sending is not configured in this example.")
    except Exception as e:
        otp_store.pop(identifier, None)
        app.logger.exception("Failed to send OTP")
        flash("Failed to send OTP. Server error.", "danger")
        return redirect(url_for("index"))

    session['key'] = identifier
    flash("OTP sent. Check your email.", "success")
    return redirect(url_for("verify"))

@app.route("/verify", methods=["GET", "POST"])
def verify():
    key = session.get('key')
    if not key:
        flash("Start by requesting an OTP.", "warning")
        return redirect(url_for("index"))

    data = otp_store.get(key)
    if request.method == "GET":
        return render_template("verify.html", identifier=key)

    otp_input = request.form.get("otp", "").strip()
    if not otp_input:
        flash("Enter the OTP code.", "danger")
        return redirect(url_for("verify"))

    if not data:
        flash("No OTP request found or it expired. Request a new one.", "danger")
        return redirect(url_for("index"))

    data["attempts"] += 1
    if data["attempts"] > MAX_VERIFY_ATTEMPTS:
        otp_store.pop(key, None)
        flash("Too many wrong attempts. OTP invalidated. Request a new one.", "danger")
        return redirect(url_for("index"))

    if time.time() > data["expiry"]:
        otp_store.pop(key, None)
        flash("OTP expired. Request a new one.", "danger")
        return redirect(url_for("index"))
    if verify_otp_hash(otp_input, data["hash"]):
        otp_store.pop(key, None)
        session.pop('key', None)
        session['authenticated'] = True
        session['auth_at'] = time.time()
        return redirect(url_for("success"))
    else:
        flash(f"Incorrect OTP. Attempts left: {MAX_VERIFY_ATTEMPTS - data['attempts']}", "danger")
        return redirect(url_for("verify"))

@app.route("/success")
def success():
    if not session.get('authenticated'):
        flash("You are not authenticated.", "warning")
        return redirect(url_for("index"))
    return render_template("success.html")

@app.route("/api/request-otp", methods=["POST"])
def api_request_otp():
    payload = request.json or {}
    identifier = payload.get("identifier", "").strip()
    medium = payload.get("medium", "email")
    
    return jsonify({"status":"not-implemented"}), 501

if __name__ == "__main__":
    app.run(debug=True)
