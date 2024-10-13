import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.ensemble import StackingClassifier
from sklearn.metrics import accuracy_score
import joblib
import os

# Load dataset
data_path = r'malware_dataset_with_is_malicious.csv'
data = pd.read_csv(data_path)
print("Data loaded successfully.")
print(f"Columns in the dataset: {data.columns.tolist()}")

# Preprocess data: Create a target variable based on family (you can modify this logic)
def preprocess_data(data):
    # Mark certain malware families as malicious (1) and others as benign (0)
    malicious_families = ['Backdoor', 'CryptoLocker', 'Keylogger', 'Worm', 'Trojan']
    data['is_malicious'] = data['family'].apply(lambda x: 1 if x in malicious_families else 0)

    # Drop unnecessary columns (like 'family', 'category' if not needed)
    X = data.drop(['family', 'is_malicious'], axis=1)
    y = data['is_malicious']

    # Convert categorical variables into one-hot encoding
    X = pd.get_dummies(X)

    return X, y

# Split the dataset and train the model
def train_model(X, y):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Create a hybrid model with RandomForest and SVM using Stacking
    estimators = [
        ('rf', RandomForestClassifier(n_estimators=100, random_state=42)),
        ('svm', SVC(probability=True, random_state=42))
    ]
    model = StackingClassifier(estimators=estimators, final_estimator=RandomForestClassifier())
    model.fit(X_train, y_train)

    # Evaluate the model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model training completed.\nAccuracy on Test Set: {accuracy * 100:.2f}%")
    
    return model, X_train.columns  # Return the trained model and the feature names

# Save the trained model and feature names
def save_model(model, feature_names, model_filename, features_filename):
    os.makedirs(os.path.dirname(model_filename), exist_ok=True)
    joblib.dump(model, model_filename)
    joblib.dump(feature_names, features_filename)
    print(f"Model saved as {model_filename}")
    print(f"Feature names saved as {features_filename}")

# Preprocess the data and train the model
X, y = preprocess_data(data)
model, feature_names = train_model(X, y)

# Save the model and feature names to .pkl files
model_path = r'models\malware_detection_model.pkl'
features_path = r'model_features.pkl'
save_model(model, feature_names, model_path, features_path)
