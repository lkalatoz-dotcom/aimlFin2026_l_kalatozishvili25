import numpy as np
import tensorflow as tf
from tensorflow.keras import layers, models

# -----------------------------
# 1. Generate Synthetic Dataset
# -----------------------------

num_samples = 1000

# Simulated traffic feature matrices (10x10, single channel)
X = np.random.rand(num_samples, 10, 10, 1)

# Binary labels: 0 = normal traffic, 1 = malicious traffic
y = np.random.randint(0, 2, num_samples)

# Split dataset into training and testing sets (80/20)
split_index = int(0.8 * num_samples)

X_train = X[:split_index]
X_test = X[split_index:]
y_train = y[:split_index]
y_test = y[split_index:]

print("Training samples:", X_train.shape[0])
print("Testing samples:", X_test.shape[0])

# -----------------------------
# 2. Build CNN Model
# -----------------------------

model = models.Sequential([
    layers.Conv2D(32, (3,3), activation='relu', input_shape=(10,10,1)),
    layers.MaxPooling2D((2,2)),

    layers.Conv2D(64, (3,3), activation='relu'),
    layers.MaxPooling2D((2,2)),

    layers.Flatten(),
    layers.Dense(64, activation='relu'),
    layers.Dense(1, activation='sigmoid')
])

# Show model architecture
model.summary()

# -----------------------------
# 3. Compile Model
# -----------------------------

model.compile(
    optimizer='adam',
    loss='binary_crossentropy',
    metrics=['accuracy']
)

# -----------------------------
# 4. Train Model
# -----------------------------

history = model.fit(
    X_train,
    y_train,
    epochs=5,
    batch_size=32,
    validation_data=(X_test, y_test)
)

# -----------------------------
# 5. Evaluate Model
# -----------------------------

loss, accuracy = model.evaluate(X_test, y_test)

print("\nTest Loss:", loss)
print("Test Accuracy:", accuracy)
