from scapy.all import sniff, IP, TCP, UDP
import numpy as np
import pandas as pd
import joblib
import tensorflow as tf
from realtime_queue import realtime_queue

# ===============================
# Load Model & Tools
# ===============================

model = tf.keras.models.load_model("ids_cnn_transformer_smote.keras")

scaler = joblib.load("scaler.save")

encoders = joblib.load("feature_encoders.save")

label_encoder = joblib.load("label_encoder.save")

print("All models loaded ✅")


# ===============================
# Column Order (Must match training)
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
# Safe Encoder (Handle Unknown)
# ===============================

def safe_encode(encoder, value, default=0):

    if value in encoder.classes_:
        return encoder.transform([value])[0]
    else:
        return default


# ===============================
# Counters (For Demo Stats)
# ===============================

packet_count = 0


# ===============================
# Packet Processing
# ===============================

def process_packet(pkt):

    global packet_count
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


    # ---------------------------
    # Basic Feature Extraction
    # (Demo Version)
    # ---------------------------

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


    # ---------------------------
    # Create DataFrame
    # ---------------------------

    df = pd.DataFrame([row], columns=columns)


    # ---------------------------
    # Encode Categorical
    # ---------------------------

    for c in ["protocol_type", "service", "flag"]:
        df[c] = df[c].apply(
            lambda x: safe_encode(encoders[c], x)
        )


    # ---------------------------
    # Scale
    # ---------------------------

    X = scaler.transform(df)


    # ---------------------------
    # Reshape
    # ---------------------------

    X = X.reshape(1, X.shape[1], 1)


    # ---------------------------
    # Predict
    # ---------------------------

    pred = model.predict(X, verbose=0)

    cls = np.argmax(pred)

    conf = np.max(pred) * 100


    # ---------------------------
    # Decode Label
    # ---------------------------

    attack = label_encoder.inverse_transform([cls])[0]


    # ---------------------------
    # Display & Send to Queue
    # ---------------------------

    # THIS IS THE CRITICAL FIX - FORMAT AS STRING WITH COMMAS
    log_data = f"Packet:{packet_count}, Protocol:{proto}, Attack:{attack}, Confidence:{conf:.2f}%"

    # Put formatted string into queue
    if not realtime_queue.full():
        realtime_queue.put(log_data)

    # Print to console
    print(log_data)


# ===============================
# Start Sniffing
# ===============================

print("🚀 Realtime IDS Started...")

sniff(prn=process_packet, store=0)


'''from scapy.all import sniff, IP, TCP, UDP
import numpy as np
import pandas as pd
import joblib
import tensorflow as tf
from realtime_queue import realtime_queue

# ===============================
# Load Model & Tools
# ===============================

model = tf.keras.models.load_model("ids_cnn_transformer_smote.keras")

scaler = joblib.load("scaler.save")

encoders = joblib.load("feature_encoders.save")

label_encoder = joblib.load("label_encoder.save")

print("All models loaded ✅")


# ===============================
# Column Order (Must match training)
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
# Safe Encoder (Handle Unknown)
# ===============================

def safe_encode(encoder, value, default=0):

    if value in encoder.classes_:
        return encoder.transform([value])[0]
    else:
        return default


# ===============================
# Counters (For Demo Stats)
# ===============================

packet_count = 0


# ===============================
# Packet Processing
# ===============================

def process_packet(pkt):

    global packet_count
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


    # ---------------------------
    # Basic Feature Extraction
    # (Demo Version)
    # ---------------------------

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


    # ---------------------------
    # Create DataFrame
    # ---------------------------

    df = pd.DataFrame([row], columns=columns)


    # ---------------------------
    # Encode Categorical
    # ---------------------------

    for c in ["protocol_type", "service", "flag"]:
        df[c] = df[c].apply(
            lambda x: safe_encode(encoders[c], x)
        )


    # ---------------------------
    # Scale
    # ---------------------------

    X = scaler.transform(df)


    # ---------------------------
    # Reshape
    # ---------------------------

    X = X.reshape(1, X.shape[1], 1)


    # ---------------------------
    # Predict
    # ---------------------------

    pred = model.predict(X, verbose=0)

    cls = np.argmax(pred)

    conf = np.max(pred) * 100


    # ---------------------------
    # Decode Label
    # ---------------------------

    attack = label_encoder.inverse_transform([cls])[0]


    # ---------------------------
    # Display
    # ---------------------------

    log_data  = (
        f"Packet:{packet_count}, "
        f"Protocol:{proto}, "
        f"Attack:{attack}, "
        f"Confidence:{conf:.2f}%\n"
    )

    if not realtime_queue.full():
        realtime_queue.put(log_data)

    print(log_data)


# ===============================
# Start Sniffing
# ===============================

print("🚀 Realtime IDS Started...")

sniff(prn=process_packet, store=0)
'''