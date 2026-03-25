"""
=============================================================
  MERGED IDS APPLICATION
  - User Login / Register (MySQL)
  - Manual / Dataset Single-Value Prediction
  - Real-time Packet Sniffer Dashboard (SocketIO)
=============================================================
"""

from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from flask_socketio import SocketIO, emit
import mysql.connector
import numpy as np
import pandas as pd
import joblib
import tensorflow as tf
from threading import Thread, Lock
from queue import Queue
from scapy.all import sniff, IP, TCP, UDP
import time

# ──────────────────────────────────────────
# SPEED CONTROL  (seconds between packets)
# 0 = fastest  |  2.0 = very slow
# ──────────────────────────────────────────
PACKET_DELAY = 2.0

# ──────────────────────────────────────────
# Flask + SocketIO setup
# ──────────────────────────────────────────
app = Flask(__name__)
app.secret_key = "secret123"
socketio = SocketIO(app, cors_allowed_origins="*")

# ──────────────────────────────────────────
# Load ML Models  (once, at startup)
# ──────────────────────────────────────────
print("🔄 Loading ML models...")
model         = tf.keras.models.load_model("ids_cnn_transformer_smote.keras")
scaler        = joblib.load("scaler.save")
encoders      = joblib.load("feature_encoders.save")
label_encoder = joblib.load("label_encoder.save")
print("✅ All models loaded")

# ──────────────────────────────────────────
# Feature Columns (41 KDD features)
# ──────────────────────────────────────────
columns = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "lnum_compromised","lroot_shell","lsu_attempted","lnum_root",
    "lnum_file_creations","lnum_shells","lnum_access_files","lnum_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate"
]

# ──────────────────────────────────────────
# DB Helper
# ──────────────────────────────────────────
def get_db():
    return mysql.connector.connect(
        user='root', password='', host='localhost',
        database='26NetworkIntrusionpy'
    )

# ──────────────────────────────────────────
# Real-time Sniffer State
# ──────────────────────────────────────────
realtime_queue = Queue(maxsize=1000)
packet_count   = 0
stats_lock     = Lock()

stats = {
    'total_packets'        : 0,
    'attacks_detected'     : 0,
    'normal_packets'       : 0,
    'attack_types'         : {},
    'protocol_distribution': {'tcp': 0, 'udp': 0, 'icmp': 0},
    'recent_logs'          : []
}

# ──────────────────────────────────────────
# Packet Processing
# ──────────────────────────────────────────
def safe_encode(encoder, value, default=0):
    return encoder.transform([value])[0] if value in encoder.classes_ else default

def process_packet(pkt):
    global packet_count
    time.sleep(PACKET_DELAY)
    packet_count += 1

    if IP not in pkt:
        return

    proto      = "tcp" if TCP in pkt else ("udp" if UDP in pkt else "icmp")
    src_bytes  = len(pkt)

    row = {
        "duration": 0, "protocol_type": proto, "service": "http", "flag": "SF",
        "src_bytes": src_bytes, "dst_bytes": 0, "land": 0, "wrong_fragment": 0,
        "urgent": 0, "hot": 0, "num_failed_logins": 0, "logged_in": 1,
        "lnum_compromised": 0, "lroot_shell": 0, "lsu_attempted": 0, "lnum_root": 0,
        "lnum_file_creations": 0, "lnum_shells": 0, "lnum_access_files": 0,
        "lnum_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0,
        "count": packet_count, "srv_count": packet_count,
        "serror_rate": 0, "srv_serror_rate": 0, "rerror_rate": 0, "srv_rerror_rate": 0,
        "same_srv_rate": 1, "diff_srv_rate": 0, "srv_diff_host_rate": 0,
        "dst_host_count": packet_count, "dst_host_srv_count": packet_count,
        "dst_host_same_srv_rate": 1, "dst_host_diff_srv_rate": 0,
        "dst_host_same_src_port_rate": 0, "dst_host_srv_diff_host_rate": 0,
        "dst_host_serror_rate": 0, "dst_host_srv_serror_rate": 0,
        "dst_host_rerror_rate": 0, "dst_host_srv_rerror_rate": 0
    }

    df = pd.DataFrame([row], columns=columns)
    for c in ["protocol_type", "service", "flag"]:
        df[c] = df[c].apply(lambda x: safe_encode(encoders[c], x))

    X      = scaler.transform(df).reshape(1, len(columns), 1)
    pred   = model.predict(X, verbose=0)
    cls    = np.argmax(pred)
    conf   = np.max(pred) * 100
    attack = label_encoder.inverse_transform([cls])[0]

    log_data = f"Packet:{packet_count}, Protocol:{proto}, Attack:{attack}, Confidence:{conf:.2f}%"
    if not realtime_queue.full():
        realtime_queue.put(log_data)
    print(log_data)

def start_sniffer():
    print(f"🚀 Packet sniffer started (delay={PACKET_DELAY}s)...")
    sniff(prn=process_packet, store=0)

def parse_log(log_data):
    try:
        return {k: v for part in log_data.split(', ') if ':' in part for k, v in [part.split(':', 1)]}
    except Exception:
        return None

def queue_monitor():
    print("📡 Queue monitor started...")
    while True:
        try:
            if not realtime_queue.empty():
                parsed = parse_log(realtime_queue.get())
                if parsed:
                    with stats_lock:
                        stats['total_packets'] = int(parsed.get('Packet', 0))
                        attack   = parsed.get('Attack', 'normal')
                        protocol = parsed.get('Protocol', 'unknown').lower()
                        confidence = str(parsed.get('Confidence', '0')).replace('%', '')

                        if protocol in stats['protocol_distribution']:
                            stats['protocol_distribution'][protocol] += 1

                        if attack.lower() != 'normal':
                            stats['attacks_detected'] += 1
                            stats['attack_types'][attack] = stats['attack_types'].get(attack, 0) + 1
                        else:
                            stats['normal_packets'] += 1

                        entry = {
                            'packet'    : parsed.get('Packet', '0'),
                            'protocol'  : protocol,
                            'attack'    : attack,
                            'confidence': confidence,
                            'timestamp' : time.strftime('%H:%M:%S')
                        }
                        stats['recent_logs'].insert(0, entry)
                        if len(stats['recent_logs']) > 100:
                            stats['recent_logs'] = stats['recent_logs'][:100]

                    socketio.emit('new_packet',    entry,       namespace='/ids')
                    socketio.emit('stats_update',  get_stats(), namespace='/ids')
            time.sleep(0.1)
        except Exception as e:
            print(f"❌ Queue monitor error: {e}")
            time.sleep(1)

def get_stats():
    with stats_lock:
        return {
            'total_packets'        : stats['total_packets'],
            'attacks_detected'     : stats['attacks_detected'],
            'normal_packets'       : stats['normal_packets'],
            'attack_types'         : stats['attack_types'],
            'protocol_distribution': stats['protocol_distribution'],
            'recent_logs'          : stats['recent_logs'][:20]
        }

# ══════════════════════════════════════════
#  ROUTES — Authentication
# ══════════════════════════════════════════

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/register")
def register():
    return render_template("register.html")

# ── Register (POST) ──────────────────────
@app.route("/newuser", methods=["POST"])
def newuser():
    name     = request.form["name"]
    mobile   = request.form["mobile"]
    email    = request.form["email"]
    password = request.form["password"]

    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM regtb WHERE email=%s", (email,))
    if cursor.fetchone():
        conn.close()
        flash('Email already registered!')
        return render_template('register.html')

    cursor.execute(
        "INSERT INTO regtb VALUES ('', %s, %s, %s, %s)",
        (name, mobile, email, password)
    )
    conn.commit()
    conn.close()
    flash('Account created! Please login.')
    return render_template('login.html')

# ── Login (POST) ─────────────────────────
@app.route("/ulogin", methods=["POST"])
def ulogin():
    email    = request.form["email"]
    password = request.form["password"]

    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM regtb WHERE email=%s AND Password=%s", (email, password))
    data = cursor.fetchone()
    conn.close()

    if data is None:
        flash('Invalid email or password.')
        return render_template('login.html')

    session['user_email'] = email
    session['user_name']  = data[1]          # name column
    return redirect(url_for('prediction_page'))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('home'))

# ══════════════════════════════════════════
#  ROUTES — Manual Prediction
# ══════════════════════════════════════════

@app.route("/prediction")
def prediction_page():
    if 'user_email' not in session:
        flash('Please login first.')
        return redirect(url_for('login'))
    return render_template("Prediction.html")

@app.route("/predict", methods=["POST"])
def predict_ids():
    if 'user_email' not in session:
        return redirect(url_for('login'))

    raw    = request.form.get("raw", "")
    result = confidence = ""

    try:
        values = [v.strip() for v in raw.split(",")]
        if len(values) != len(columns):
            raise ValueError(f"Expected {len(columns)} values, got {len(values)}")

        data = pd.DataFrame([values], columns=columns)

        for col in columns:
            if col not in ["protocol_type", "service", "flag"]:
                data[col] = data[col].astype(float)

        for col in ["protocol_type", "service", "flag"]:
            data[col] = encoders[col].transform(data[col])

        X      = scaler.transform(data).reshape(1, len(columns), 1)
        pred   = model.predict(X)
        cls    = np.argmax(pred)
        conf   = np.max(pred) * 100
        result = label_encoder.inverse_transform([cls])[0]
        confidence = f"{round(conf, 2)} %"

    except Exception as e:
        result     = f"❌ Error: {e}"
        confidence = ""

    return render_template("Prediction.html", result=result, confidence=confidence)

# ══════════════════════════════════════════
#  ROUTES — Real-time Dashboard
# ══════════════════════════════════════════

@app.route("/dashboard")
def dashboard():
    if 'user_email' not in session:
        flash('Please login first.')
        return redirect(url_for('login'))
    return render_template("dashboard.html")

@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())

# ── SocketIO ─────────────────────────────
@socketio.on('connect', namespace='/ids')
def handle_connect():
    print('✅ Client connected')
    emit('stats_update', get_stats())

@socketio.on('disconnect', namespace='/ids')
def handle_disconnect():
    print('❌ Client disconnected')

# ══════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════
if __name__ == '__main__':
    # Start background threads
    Thread(target=queue_monitor,  daemon=True).start()
    Thread(target=start_sniffer,  daemon=True).start()
    time.sleep(1)

    print("🌐 Merged IDS App running → http://localhost:5000")
    print(f"⚡ Packet delay: {PACKET_DELAY}s")
    print("⚠️  Run with sudo for packet sniffing privileges")
    socketio.run(app, debug=False, host='0.0.0.0', port=5000,
                 allow_unsafe_werkzeug=True)