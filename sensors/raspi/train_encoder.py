import numpy as np
import tensorflow as tf
from tensorflow import keras
from sklearn.preprocessing import StandardScaler
import joblib

# Simuler des données normales (basées sur generate_data)
def generate_normal_data(n_samples=1000):
    hr = np.random.randint(70, 90, n_samples)
    spo2 = np.random.uniform(95.0, 99.0, n_samples)
    temp = np.random.uniform(36.5, 37.0, n_samples)
    systolic = np.random.randint(110, 130, n_samples)
    diastolic = np.random.randint(70, 85, n_samples)
    glucose = np.random.uniform(4.5, 6.5, n_samples)
    rr = np.random.randint(12, 20, n_samples)
    return np.column_stack([hr, spo2, temp, systolic, diastolic, glucose, rr])

X = generate_normal_data()
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Autoencoder
inputs = keras.Input(shape=(7,))
encoded = keras.layers.Dense(5, activation='relu')(inputs)
encoded = keras.layers.Dense(3, activation='relu')(encoded)
decoded = keras.layers.Dense(5, activation='relu')(encoded)
decoded = keras.layers.Dense(7, activation='linear')(decoded)

autoencoder = keras.Model(inputs, decoded)
autoencoder.compile(optimizer='adam', loss='mse')
autoencoder.fit(X_scaled, X_scaled, epochs=50, batch_size=32, verbose=1)

# Sauvegarder le modèle et le scaler
autoencoder.save("autoencoder_model.h5")
joblib.dump(scaler, "scaler.pkl")

converter = tf.lite.TFLiteConverter.from_keras_model(autoencoder)
tflite_model = converter.convert()
with open("autoencoder_model.tflite", "wb") as f:
    f.write(tflite_model)
