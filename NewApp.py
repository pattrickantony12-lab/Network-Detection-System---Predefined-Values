"""
Combined IDS + Flask Dashboard Runner (WITH SPEED CONTROL)
Runs both the packet sniffer and web dashboard in the same process
"""

from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
from threading import Thread, Lock
import time
from queue import Queue
from scapy.all import sniff, IP, TCP, UDP
import numpy as np
import pandas as pd
import joblib
import tensorflow as tf

# ===============================
# SPEED CONTROL SETTINGS
# ===============================
PACKET_DELAY = 2.0  # Delay in seconds between processing packets (0.5 = half second)
# Change this value:
# 0 = No delay (fastest)
# 0.2 = Very fast
# 0.5 = Medium (recommended)
# 1.0 = Slow
# 2.0 = Very slow

# ===============================
# Shared Queue
# ===============================
realtime_queue = Queue(maxsize=1000)

# ===============================
# Load ML Models
# ===============================
print("🔄 Loading ML models...")
model = tf.keras.models.load_model("ids_cnn_transformer_smote.keras")
scaler = joblib.load("scaler.save")
encoders = joblib.load("feature_encoders.save")
label_encoder = joblib.load("label_encoder.save")
print("✅ All models loaded")

# ===============================
# Feature Columns
# ===============================
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

# ===============================
# IDS Functions
# ===============================
packet_count = 0

def safe_encode(encoder, value, default=0):
    if value in encoder.classes_:
        return encoder.transform([value])[0]
    else:
        return default

def process_packet(pkt):
    global packet_count

    # ADD DELAY HERE TO SLOW DOWN
    time.sleep(PACKET_DELAY)

    packet_count += 1

    if IP not in pkt:
        return

    # Detect Protocol
    if TCP in pkt:
        proto = "tcp"
    elif UDP in pkt:
        proto = "udp"
    else:
        proto = "icmp"

    src_bytes = len(pkt)
    dst_bytes = 0

    # Basic Feature Extraction
    row = {
        "duration": 0,
        "protocol_type": proto,
        "service": "http",
        "flag": "SF",
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 1,
        "lnum_compromised": 0,
        "lroot_shell": 0,
        "lsu_attempted": 0,
        "lnum_root": 0,
        "lnum_file_creations": 0,
        "lnum_shells": 0,
        "lnum_access_files": 0,
        "lnum_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": packet_count,
        "srv_count": packet_count,
        "serror_rate": 0,
        "srv_serror_rate": 0,
        "rerror_rate": 0,
        "srv_rerror_rate": 0,
        "same_srv_rate": 1,
        "diff_srv_rate": 0,
        "srv_diff_host_rate": 0,
        "dst_host_count": packet_count,
        "dst_host_srv_count": packet_count,
        "dst_host_same_srv_rate": 1,
        "dst_host_diff_srv_rate": 0,
        "dst_host_same_src_port_rate": 0,
        "dst_host_srv_diff_host_rate": 0,
        "dst_host_serror_rate": 0,
        "dst_host_srv_serror_rate": 0,
        "dst_host_rerror_rate": 0,
        "dst_host_srv_rerror_rate": 0
    }

    # Create DataFrame
    df = pd.DataFrame([row], columns=columns)

    # Encode Categorical
    for c in ["protocol_type", "service", "flag"]:
        df[c] = df[c].apply(lambda x: safe_encode(encoders[c], x))

    # Scale
    X = scaler.transform(df)

    # Reshape
    X = X.reshape(1, X.shape[1], 1)

    # Predict
    pred = model.predict(X, verbose=0)
    cls = np.argmax(pred)
    conf = np.max(pred) * 100

    # Decode Label
    attack = label_encoder.inverse_transform([cls])[0]

    # Format and queue
    log_data = f"Packet:{packet_count}, Protocol:{proto}, Attack:{attack}, Confidence:{conf:.2f}%"

    if not realtime_queue.full():
        realtime_queue.put(log_data)

    print(log_data)

def start_packet_sniffing():
    """Start packet sniffing in background thread"""
    print(f"🚀 Starting packet sniffer (Speed: {PACKET_DELAY}s delay)...")
    sniff(prn=process_packet, store=0)

# ===============================
# Flask Application
# ===============================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'san'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global statistics
stats = {
    'total_packets': 0,
    'attacks_detected': 0,
    'normal_packets': 0,
    'attack_types': {},
    'protocol_distribution': {'tcp': 0, 'udp': 0, 'icmp': 0},
    'recent_logs': []
}
stats_lock = Lock()

def parse_log_data(log_data):
    """Parse log data string"""
    try:
        if isinstance(log_data, str):
            parts = log_data.strip().split(', ')
            data = {}
            for part in parts:
                if ':' in part:
                    key, value = part.split(':', 1)
                    data[key] = value
            return data
        return None
    except Exception as e:
        print(f"Error parsing log data: {e}")
        return None

def queue_monitor():
    """Monitor queue and broadcast updates"""
    print("📡 Queue monitor started...")

    while True:
        try:
            if not realtime_queue.empty():
                log_data = realtime_queue.get()
                print(f"📦 Received from queue: {log_data}")

                parsed = parse_log_data(log_data)

                if parsed:
                    with stats_lock:
                        stats['total_packets'] = int(parsed.get('Packet', 0))

                        attack = parsed.get('Attack', 'normal')
                        protocol = parsed.get('Protocol', 'unknown').lower()
                        confidence = str(parsed.get('Confidence', '0')).replace('%', '')

                        if protocol in stats['protocol_distribution']:
                            stats['protocol_distribution'][protocol] += 1

                        if attack.lower() != 'normal':
                            stats['attacks_detected'] += 1
                            if attack in stats['attack_types']:
                                stats['attack_types'][attack] += 1
                            else:
                                stats['attack_types'][attack] = 1
                        else:
                            stats['normal_packets'] += 1

                        log_entry = {
                            'packet': parsed.get('Packet', '0'),
                            'protocol': protocol,
                            'attack': attack,
                            'confidence': confidence,
                            'timestamp': time.strftime('%H:%M:%S')
                        }
                        stats['recent_logs'].insert(0, log_entry)
                        if len(stats['recent_logs']) > 100:
                            stats['recent_logs'] = stats['recent_logs'][:100]

                    print(f"📤 Broadcasting: {log_entry}")
                    socketio.emit('new_packet', log_entry, namespace='/ids')
                    socketio.emit('stats_update', get_stats(), namespace='/ids')

            time.sleep(0.1)
        except Exception as e:
            print(f"❌ Error in queue monitor: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(1)

def get_stats():
    """Get current statistics"""
    with stats_lock:
        return {
            'total_packets': stats['total_packets'],
            'attacks_detected': stats['attacks_detected'],
            'normal_packets': stats['normal_packets'],
            'attack_types': stats['attack_types'],
            'protocol_distribution': stats['protocol_distribution'],
            'recent_logs': stats['recent_logs'][:20]
        }

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/stats')
def api_stats():
    return jsonify(get_stats())

@socketio.on('connect', namespace='/ids')
def handle_connect():
    print('✅ Client connected')
    emit('stats_update', get_stats())

@socketio.on('disconnect', namespace='/ids')
def handle_disconnect():
    print('❌ Client disconnected')

# ===============================
# Main Entry Point
# ===============================
if __name__ == '__main__':
    # Start queue monitor thread
    monitor_thread = Thread(target=queue_monitor, daemon=True)
    monitor_thread.start()

    # Start packet sniffing thread
    sniffer_thread = Thread(target=start_packet_sniffing, daemon=True)
    sniffer_thread.start()

    # Give sniffer a moment to start
    time.sleep(1)

    # Run Flask server
    print("🌐 Flask Dashboard starting on http://localhost:5000")
    print(f"⚡ Packet processing speed: {PACKET_DELAY}s delay between packets")
    print("⚠️  Note: Run this script with sudo/administrator privileges for packet sniffing")
    socketio.run(app, debug=False, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)