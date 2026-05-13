from sklearn.ensemble import IsolationForest
import numpy as np

# Example training dataset
training_data = np.array([
    [10, 0, 0],
    [20, 1, 0],
    [15, 0, 1],
    [500, 10, 8]
])

# Create model
model = IsolationForest()

# Train model
model.fit(training_data)

print("ML model trained successfully")