from flask import Flask, request, jsonify, render_template
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, get_jwt
from flask_cors import CORS
from datetime import datetime
import sqlite3
import joblib
import pandas as pd
import os

from auth.auth import auth_bp, init_db

app = Flask(__name__)
CORS(app)

# ─── Config ───────────────────────────────────────────────────────
app.config['JWT_SECRET_KEY'] = 'ids-iam-super-secret-key-2024'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False

jwt = JWTManager(app)

# Register auth blueprint
app.register_blueprint(auth_bp, url_prefix='/auth')

# ─── IDS Routes ───────────────────────────────────────────────────

@app.route('/ids/analyze', methods=['POST'])
@jwt_required()
def analyze_traffic():
    """Analyze network traffic — analysts and admins only"""
    claims = get_jwt()
    if claims.get('role') not in ['admin', 'analyst']:
        return jsonify({'error': 'Analyst or Admin access required'}), 403

    data = request.get_json()
    
    # Expected features from request
    features = [
        data.get('duration', 0),
        data.get('src_bytes', 0),
        data.get('dst_bytes', 0),
        data.get('land', 0),
        data.get('wrong_fragment', 0),
        data.get('urgent', 0),
        data.get('hot', 0),
        data.get('num_failed_logins', 0),
        data.get('logged_in', 0),
        data.get('num_compromised', 0),
        data.get('count', 0),
        data.get('srv_count', 0),
        data.get('serror_rate', 0),
        data.get('rerror_rate', 0),
        data.get('same_srv_rate', 0),
        data.get('diff_srv_rate', 0),
        data.get('dst_host_count', 0),
        data.get('dst_host_srv_count', 0),
        data.get('dst_host_same_srv_rate', 0),
        data.get('dst_host_serror_rate', 0),
    ]

    try:
        model = joblib.load('model/ids_model.pkl')
        feature_names = [
            'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
            'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
            'count', 'srv_count', 'serror_rate', 'rerror_rate', 'same_srv_rate',
            'diff_srv_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_serror_rate'
        ]
        features_df = pd.DataFrame([features], columns=feature_names)
        prediction = model.predict(features_df)[0]
        confidence = round(model.predict_proba(features_df).max() * 100, 2)

        # Determine severity
        if prediction == 'attack':
            if confidence > 95:
                severity = 'CRITICAL'
            elif confidence > 85:
                severity = 'HIGH'
            elif confidence > 70:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
        else:
            severity = 'NONE'

        # Save alert to DB
        if prediction == 'attack':
            save_alert(prediction, confidence, severity, data.get('src_ip', 'unknown'))

        return jsonify({
            'prediction': prediction,
            'confidence': confidence,
            'severity': severity,
            'is_attack': prediction == 'attack',
            'timestamp': datetime.now().isoformat()
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


def save_alert(prediction, confidence, severity, src_ip):
    conn = sqlite3.connect('database.db')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prediction TEXT,
            confidence REAL,
            severity TEXT,
            src_ip TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.execute(
        "INSERT INTO alerts (prediction, confidence, severity, src_ip) VALUES (?, ?, ?, ?)",
        (prediction, confidence, severity, src_ip)
    )
    conn.commit()
    conn.close()


@app.route('/ids/alerts', methods=['GET'])
@jwt_required()
def get_alerts():
    """Get all IDS alerts"""
    claims = get_jwt()
    if claims.get('role') not in ['admin', 'analyst']:
        return jsonify({'error': 'Insufficient permissions'}), 403

    conn = sqlite3.connect('database.db')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prediction TEXT,
            confidence REAL,
            severity TEXT,
            src_ip TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    alerts = conn.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 50"
    ).fetchall()
    conn.close()

    return jsonify([{
        'id': a[0],
        'prediction': a[1],
        'confidence': a[2],
        'severity': a[3],
        'src_ip': a[4],
        'timestamp': a[5]
    } for a in alerts]), 200


@app.route('/ids/stats', methods=['GET'])
@jwt_required()
def get_stats():
    """Dashboard statistics"""
    conn = sqlite3.connect('database.db')
    
    # Ensure alerts table exists
    conn.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prediction TEXT,
            confidence REAL,
            severity TEXT,
            src_ip TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    critical = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'").fetchone()[0]
    high = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'").fetchone()[0]
    blocked_ips = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    total_logins = conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='LOGIN_SUCCESS'").fetchone()[0]
    conn.close()

    return jsonify({
        'total_alerts': total_alerts,
        'critical_alerts': critical,
        'high_alerts': high,
        'blocked_ips': blocked_ips,
        'total_users': total_users,
        'total_logins': total_logins
    }), 200


# ─── Dashboard Route ──────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-eval' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "img-src 'self' data:;"
    )
    return response

# ─── Run ──────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    print("Database initialized")
    print("Starting IDS-IAM System...")
    print("Visit: http://127.0.0.1:5000")
    app.run(debug=True, port=5000)