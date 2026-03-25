import numpy as np
import pandas as pd
import joblib
import tensorflow as tf

model = tf.keras.models.load_model("ids_cnn_transformer_smote.keras")
scaler = joblib.load("scaler.save")
encoders = joblib.load("feature_encoders.save")
label_encoder = joblib.load("label_encoder.save")

# Column Order (MUST MATCH TRAINING CSV)
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
result = ""
confidence = ""
raw = "0,icmp,ecr_i,SF,1032,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,511,511,0,0,0,0,1,0,0,158,13,0.08,0.02,0.08,0,0,0,0,0"
try:
    # Split by comma
    values = raw.split(",")

    # Create DataFrame
    data = pd.DataFrame([values], columns=columns)

    # Convert numeric columns
    for col in columns:
        if col not in ["protocol_type", "service", "flag"]:
            data[col] = data[col].astype(float)

    # Encode categorical
    for col in ["protocol_type", "service", "flag"]:
        data[col] = encoders[col].transform(data[col])

    # Scale
    X = scaler.transform(data)

    # Reshape
    X = X.reshape(1, X.shape[1], 1)

    # Predict
    pred = model.predict(X)

    pred_class = np.argmax(pred)
    conf = np.max(pred) * 100

    # Decode label
    attack = label_encoder.inverse_transform([pred_class])[0]

    result = attack
    confidence = str(round(conf, 2)) + " %"
    print(result)
    print(confidence)
except Exception as e:
            result = "❌ Error: " + str(e)

