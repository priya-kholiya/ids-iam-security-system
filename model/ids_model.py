import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

# Column names for KDD Cup dataset
COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'label'
]

# Features we'll use for training
FEATURES = [
    'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
    'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
    'count', 'srv_count', 'serror_rate', 'rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_serror_rate'
]

def load_and_preprocess():
    print("Loading dataset...")
    df = pd.read_csv('data/network_traffic.csv', names=COLUMNS)
    
    # Simplify labels: normal vs attack
    df['label'] = df['label'].apply(
        lambda x: 'normal' if x.strip('.') == 'normal' else 'attack'
    )
    
    X = df[FEATURES]
    y = df['label']
    
    print(f"Dataset loaded: {len(df)} records")
    print(f"Normal: {sum(y == 'normal')} | Attack: {sum(y == 'attack')}")
    
    return X, y

def train_model():
    X, y = load_and_preprocess()
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    print("Training Random Forest model...")
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1  # use all CPU cores
    )
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nModel Accuracy: {accuracy * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Save model
    os.makedirs('model', exist_ok=True)
    joblib.dump(model, 'model/ids_model.pkl')
    print("Model saved to model/ids_model.pkl")
    
    return model, accuracy

def predict(features):
    """
    Predict if traffic is normal or attack
    features: list of 20 numeric values matching FEATURES list
    """
    try:
        model = joblib.load('model/ids_model.pkl')
        features_df = pd.DataFrame([features], columns=FEATURES)
        prediction = model.predict(features_df)[0]
        confidence = model.predict_proba(features_df).max() * 100
        return {
            'prediction': prediction,
            'confidence': round(confidence, 2),
            'is_attack': prediction == 'attack'
        }
    except Exception as e:
        return {'error': str(e)}

if __name__ == '__main__':
    train_model()