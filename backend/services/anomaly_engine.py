import numpy as np
from sklearn.ensemble import IsolationForest

model = IsolationForest(
    contamination=0.1,
    random_state=42
)

trained = False


def extract_features(text):

    return [
        len(text),
        text.count("error"),
        text.count("fail"),
        text.count("attack"),
        text.count("scan"),
        text.count("malware"),
        text.count("ransomware")
    ]


def detect_anomaly(text):

    global trained

    features = np.array([extract_features(text)])

    if not trained:

        model.fit(features)

        trained = True

    prediction = model.predict(features)[0]

    return "anomaly" if prediction == -1 else "normal"
