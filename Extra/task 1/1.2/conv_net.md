# Convolutional Neural Network (CNN) in Cybersecurity

## 1. Introduction

Convolutional Neural Networks (CNNs) are a type of deep learning model specifically designed to process structured grid-like data, such as images or sequential signals. Unlike traditional neural networks, CNNs automatically learn hierarchical features through a combination of convolutional layers, pooling layers, and fully connected layers. Key components include:

- **Convolutional layers:** Apply learnable filters to extract local spatial or temporal features.  
- **Activation functions:** Non-linear transformations like ReLU to introduce non-linearity.  
- **Pooling layers:** Downsample feature maps, reducing dimensionality while retaining important information.  
- **Fully connected layers:** Combine high-level features for classification tasks.  
- **Softmax layer:** Produces probability distributions over output classes.

CNNs excel in image recognition, signal processing, and cybersecurity applications, including malware classification, network intrusion detection, and anomaly detection. Their ability to automatically extract features reduces the need for manual feature engineering, improving efficiency and accuracy in threat detection.

---

## 2. Practical Example: Malware Detection

In cybersecurity, CNNs can be applied to detect malware by analyzing either raw binary data or feature representations extracted from executable files. Here, we demonstrate a **synthetic dataset** for training a CNN to classify programs as benign or malicious.

### Dataset

- Total samples: 2,000 (50% benign, 50% malware)  
- Each sample represented as a 16×16 grid (simulated behavioral/binary features)  
- Labels: `0 = Benign`, `1 = Malware`  

This dataset simulates patterns that malware might exhibit, such as repeated high-value bytes or anomalous feature distributions.

---

### Python Code Example (PyTorch)

```python
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset, random_split

# Seed
np.random.seed(42)
torch.manual_seed(42)

# Generate synthetic dataset
def generate_dataset(n_samples=2000):
    X = np.random.rand(n_samples, 16, 16) * 255
    y = np.array([0]*(n_samples//2) + [1]*(n_samples//2))
    idx = np.random.permutation(n_samples)
    return X[idx].astype(np.float32), y[idx].astype(np.long)

X, y = generate_dataset()
X = X[:, np.newaxis, :, :]  # Add channel dimension

# Convert to PyTorch tensors
X_tensor = torch.tensor(X)
y_tensor = torch.tensor(y)

# Dataset and loader
dataset = TensorDataset(X_tensor, y_tensor)
train_size = int(0.8 * len(dataset))
test_size = len(dataset) - train_size
train_set, test_set = random_split(dataset, [train_size, test_size])
train_loader = DataLoader(train_set, batch_size=32, shuffle=True)
test_loader = DataLoader(test_set, batch_size=32, shuffle=False)

# CNN Model
class MalwareCNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.conv1 = nn.Conv2d(1, 16, 3, padding=1)
        self.pool = nn.MaxPool2d(2, 2)
        self.conv2 = nn.Conv2d(16, 32, 3, padding=1)
        self.fc1 = nn.Linear(32*4*4, 64)
        self.fc2 = nn.Linear(64, 2)
        self.relu = nn.ReLU()

    def forward(self, x):
        x = self.pool(self.relu(self.conv1(x)))
        x = self.pool(self.relu(self.conv2(x)))
        x = x.view(-1, 32*4*4)
        x = self.relu(self.fc1(x))
        x = self.fc2(x)
        return x

model = MalwareCNN()
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=0.001)

# Training loop
for epoch in range(5):
    running_loss = 0.0
    for inputs, labels in train_loader:
        optimizer.zero_grad()
        outputs = model(inputs)
        loss = criterion(outputs, labels)
        loss.backward()
        optimizer.step()
        running_loss += loss.item()
    print(f"Epoch {epoch+1}, Loss: {running_loss/len(train_loader):.4f}")

# Evaluation
correct = 0
total = 0
with torch.no_grad():
    for inputs, labels in test_loader:
        outputs = model(inputs)
        _, predicted = torch.max(outputs, 1)
        total += labels.size(0)
        correct += (predicted == labels).sum().item()
print(f"Test Accuracy: {correct/total:.2%}")
