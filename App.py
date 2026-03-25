from flask import Flask, render_template, request, redirect, session, url_for, flash
import mysql.connector
import numpy as np
import pandas as pd
import joblib
import tensorflow as tf

app = Flask(__name__)
app.secret_key = "secret123"


# load once
model = tf.keras.models.load_model("ids_cnn_transformer_smote.keras")
scaler = joblib.load("scaler.save")
encoders = joblib.load("feature_encoders.save")
label_encoder = joblib.load("label_encoder.save")

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


# HOME
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/register")
def register():
    return render_template("register.html")


# REGISTER
@app.route("/newuser", methods=["GET", "POST"])
def newuser():
    if request.method == "POST":
        name = request.form["name"]
        mobile = request.form["mobile"]
        email = request.form["email"]
        password = request.form["password"]

        conn = mysql.connector.connect(user='root', password='', host='localhost', database='26NetworkIntrusionpy')
        cursor = conn.cursor()
        cursor.execute("SELECT * from regtb where email='" + email + "'  ")
        data = cursor.fetchone()
        if data is None:
            conn = mysql.connector.connect(user='root', password='', host='localhost', database='26NetworkIntrusionpy')
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO regtb VALUES ('','" + name + "','" + mobile + "','" + email + "','" + password + "')")
            conn.commit()
            conn.close()

            flash('Record Saved!')
            return render_template('login.html')
        else:
            flash('Already Register This  email!')
            return render_template('register.html')

    return render_template("register.html")


# LOGIN
@app.route("/ulogin", methods=["GET", "POST"])
def ulogin():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = mysql.connector.connect(user='root', password='', host='localhost', database='26NetworkIntrusionpy')
        cursor = conn.cursor()
        cursor.execute("SELECT * from regtb where email='" + email + "' and Password='" + password + "' ")
        data = cursor.fetchone()
        if data is None:

            flash('Username or Password is wrong')
            return render_template('login.html')

        else:
            conn = mysql.connector.connect(user='root', password='', host='localhost',
                                           database='26NetworkIntrusionpy')
            cur = conn.cursor()
            cur.execute("SELECT * FROM regtb where email='" + email + "'")
            data1 = cur.fetchall()
            return render_template('Prediction.html', data=data1)


@app.route("/predict", methods=["GET","POST"])
def predict_ids():

    if request.method == "POST":
        raw = request.form["raw"]

        try:
            values = raw.split(",")

            if len(values) != len(columns):
                raise Exception(f"Expected {len(columns)} values but got {len(values)}")

            data = pd.DataFrame([values], columns=columns)

            # numeric conversion
            for col in columns:
                if col not in ["protocol_type","service","flag"]:
                    data[col] = data[col].astype(float)

            # encode categorical
            for col in ["protocol_type","service","flag"]:
                data[col] = encoders[col].transform(data[col])

            # scale
            X = scaler.transform(data)

            # reshape for CNN
            X = X.reshape(1, X.shape[1], 1)

            pred = model.predict(X)

            pred_class = np.argmax(pred)
            conf = np.max(pred) * 100

            attack = label_encoder.inverse_transform([pred_class])[0]

            result = attack
            confidence = str(round(conf,2)) + " %"

        except Exception as e:
            result = "❌ Error: " + str(e)
            confidence = ""

    return render_template("Prediction.html", result=result, confidence=confidence)



if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)
