import numpy as np
import os
import pickle
from sklearn.ensemble import IsolationForest

MODEL_PATH = 'anomaly_model.pkl'

# Training data - normal log patterns
NORMAL_LOGS = [
    "User login successful",
    "Database connection established",
    "File uploaded successfully",
    "Email sent to user@example.com",
    "System backup completed",
    "Service started on port 8080",
    "Configuration updated",
    "User session expired",
    "Cache cleared successfully",
    "Report generated",
    "API request processed",
    "Scheduled task executed",
    "Log rotation completed",
    "Health check passed",
    "Certificate renewed"
]

# Anomalous patterns for training
ANOMALOUS_LOGS = [
    "Failed login attempt from IP 192.168.1.100",
    "SQL injection detected: SELECT * FROM users",
    "Multiple authentication failures",
    "Suspicious file upload: malware.exe",
    "Port scan detected from 10.0.0.1",
    "Ransomware encryption started",
    "Rootkit installation attempt",
    "Data exfiltration to external server",
    "Privilege escalation detected",
    "Buffer overflow exploit"
]

model = None

def initialize_model():
    """
    Initialize and train the anomaly detection model once
    """
    global model
    
    if os.path.exists(MODEL_PATH):
        # Load pre-trained model
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        return
    
    # Create training dataset
    training_data = []
    
    # Add normal logs
    for log in NORMAL_LOGS:
        training_data.append(extract_features(log))
    
    # Add some anomalous logs (marked as outliers)
    for log in ANOMALOUS_LOGS[:3]:  # Limited anomalous for training
        training_data.append(extract_features(log))
    
    # Convert to numpy array
    X_train = np.array(training_data)
    
    # Train model
    model = IsolationForest(
        contamination=0.1,  # Expected proportion of outliers
        random_state=42,
        n_estimators=100
    )
    
    model.fit(X_train)
    
    # Save model
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)


def extract_features(text):
    """
    Extract numerical features from log text
    """
    text_lower = text.lower()
    
    return [
        len(text),  # Length
        text.count("error"),  # Error count
        text.count("fail"),  # Failure count
        text.count("attack"),  # Attack mentions
        text.count("scan"),  # Scan mentions
        text.count("malware"),  # Malware mentions
        text.count("ransomware"),  # Ransomware mentions
        text.count("login"),  # Login attempts
        text.count("sql"),  # SQL mentions
        text.count("inject"),  # Injection attempts
        sum(1 for word in ["admin", "root", "sudo"] if word in text_lower),  # Privilege words
        sum(1 for char in text if char.isupper()) / len(text) if text else 0,  # Uppercase ratio
    ]


def detect_anomaly(text):
    """
    Detect if log text is anomalous
    """
    if model is None:
        initialize_model()
    
    features = np.array([extract_features(text)])
    prediction = model.predict(features)[0]
    
    # IsolationForest: -1 for anomaly, 1 for normal
    return "anomaly" if prediction == -1 else "normal"


def retrain_model():
    """
    Retrain model with new data (call periodically)
    """
    global model
    if os.path.exists(MODEL_PATH):
        os.remove(MODEL_PATH)
    model = None
    initialize_model()
