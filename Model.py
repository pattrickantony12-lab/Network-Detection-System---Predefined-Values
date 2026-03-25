import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import (
    Input, Dense, Conv1D, MaxPooling1D,
    LayerNormalization, MultiHeadAttention,
    Dropout, GlobalAveragePooling1D
)
import joblib

# ===============================
# 1. Load Dataset
# ===============================

data = pd.read_csv("Dataset/Sample.csv")   # <-- Change path if needed

print("Dataset Shape:", data.shape)

# ===============================
# 2. Encode Categorical Columns
# ===============================

cat_cols = ["protocol_type", "service", "flag"]

encoders = {}   # store all feature encoders

for col in cat_cols:
    le = LabelEncoder()
    data[col] = le.fit_transform(data[col])
    encoders[col] = le   # save encoder

# Encode label
label_encoder = LabelEncoder()
data["label"] = label_encoder.fit_transform(data["label"])

# Save encoders
joblib.dump(encoders, "feature_encoders.save")
joblib.dump(label_encoder, "label_encoder.save")

# ===============================
# 3. Split X and Y
# ===============================

X = data.drop("label", axis=1)
y = data["label"]

# ===============================
# 4. Normalize Features
# ===============================

scaler = StandardScaler()
X = scaler.fit_transform(X)

joblib.dump(scaler, "scaler.save")

# ===============================
# 5. Apply SMOTE
# ===============================

print("\nBefore SMOTE:", np.bincount(y))
smote = SMOTE(random_state=42, k_neighbors=1)
X_res, y_res = smote.fit_resample(X, y)

print("After SMOTE :", np.bincount(y_res))

# ===============================
# 6. Train Test Split
# ===============================

X_train, X_test, y_train, y_test = train_test_split(
    X_res, y_res,
    test_size=0.2,
    random_state=42,
    stratify=y_res
)

# ===============================
# 7. Reshape for CNN
# ===============================


# (samples, timesteps, channels)
X_train = X_train.reshape(X_train.shape[0], X_train.shape[1], 1)
X_test  = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)

input_shape = X_train.shape[1:]


# ===============================
# 8. Transformer Block
# ===============================


def transformer_block(x, head_size, num_heads, ff_dim, dropout=0.1):

    attn = MultiHeadAttention(
        num_heads=num_heads,
        key_dim=head_size
    )(x, x)

    attn = Dropout(dropout)(attn)

    x = LayerNormalization(epsilon=1e-6)(x + attn)

    ff = Dense(ff_dim, activation="relu")(x)
    ff = Dense(x.shape[-1])(ff)
    ff = Dropout(dropout)(ff)

    return LayerNormalization(epsilon=1e-6)(x + ff)


# ===============================
# 9. Build CNN + Transformer
# ===============================


inputs = Input(shape=input_shape)

# CNN Layers
x = Conv1D(64, 3, activation="relu")(inputs)
x = MaxPooling1D(2)(x)

x = Conv1D(128, 3, activation="relu")(x)
x = MaxPooling1D(2)(x)

# Transformer
x = transformer_block(
    x,
    head_size=64,
    num_heads=4,
    ff_dim=128
)

# Pooling
x = GlobalAveragePooling1D()(x)

# Dense Layers
x = Dense(128, activation="relu")(x)
x = Dropout(0.3)(x)

outputs = Dense(len(np.unique(y_res)), activation="softmax")(x)

model = Model(inputs, outputs)

# ===============================
# 10. Compile
# ===============================

model.compile(
    optimizer="adam",
    loss="sparse_categorical_crossentropy",
    metrics=["accuracy"]
)

model.summary()

# ===============================
# 11. Train
# ===============================

history = model.fit(
    X_train, y_train,
    validation_data=(X_test, y_test),
    epochs=30,
    batch_size=64
)




import matplotlib.pyplot as plt

# Accuracy Graph
plt.figure()
plt.plot(history.history['accuracy'], label='Train Accuracy')
plt.plot(history.history['val_accuracy'], label='Validation Accuracy')

plt.title("Training vs Validation Accuracy")
plt.xlabel("Epochs")
plt.ylabel("Accuracy")
plt.legend()
plt.grid(True)
plt.show()


# Loss Graph
plt.figure()
plt.plot(history.history['loss'], label='Train Loss')
plt.plot(history.history['val_loss'], label='Validation Loss')

plt.title("Training vs Validation Loss")
plt.xlabel("Epochs")
plt.ylabel("Loss")
plt.legend()
plt.grid(True)
plt.show()


# ===============================
# 12. Evaluate
# ===============================


loss, acc = model.evaluate(X_test, y_test)
print("\nTest Accuracy:", round(acc*100,2), "%")


# ===============================
# 13. Prediction Report
# ===============================


y_pred = model.predict(X_test)
y_pred = np.argmax(y_pred, axis=1)

print("\nClassification Report:\n")
print(classification_report(
    y_test,
    y_pred,
    target_names=label_encoder.classes_
))

print("\nConfusion Matrix:\n")
print(confusion_matrix(y_test, y_pred))

import seaborn as sns
from sklearn.metrics import confusion_matrix

# Confusion Matrix
cm = confusion_matrix(y_test, y_pred)

plt.figure(figsize=(8,6))
sns.heatmap(
    cm,
    annot=True,
    fmt="d",
    cmap="Blues",
    xticklabels=label_encoder.classes_,
    yticklabels=label_encoder.classes_
)

plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.show()


# ===============================
# 14. Save Model
# ===============================


model.save("ids_cnn_transformer_smote.keras")
print("\nModel Saved Successfully ✅")
