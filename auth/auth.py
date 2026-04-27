from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt
from datetime import timedelta
import bcrypt
import sqlite3
import os

auth_bp = Blueprint('auth', __name__)

# ─── Database Setup ───────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )
    ''')
    
    # Audit log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT,
            ip_address TEXT,
            status TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Blocked IPs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE,
            reason TEXT,
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Failed attempts tracker
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS failed_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            username TEXT,
            attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create default admin user if not exists
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        hashed = bcrypt.hashpw('admin123'.encode(), bcrypt.gensalt())
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ('admin', hashed.decode(), 'admin')
        )
        print("Default admin created: username=admin, password=admin123")

    conn.commit()
    conn.close()

# ─── Helper Functions ─────────────────────────────────────────────

def log_action(username, action, ip_address, status):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log (username, action, ip_address, status) VALUES (?, ?, ?, ?)",
        (username, action, ip_address, status)
    )
    conn.commit()
    conn.close()

def is_ip_blocked(ip):
    conn = get_db()
    result = conn.execute(
        "SELECT * FROM blocked_ips WHERE ip_address = ?", (ip,)
    ).fetchone()
    conn.close()
    return result is not None

def check_and_block_ip(ip, username):
    conn = get_db()
    # Count failed attempts in last 10 minutes
    conn.execute(
        """INSERT INTO failed_attempts (ip_address, username) VALUES (?, ?)""",
        (ip, username)
    )
    conn.commit()
    
    count = conn.execute(
        """SELECT COUNT(*) as cnt FROM failed_attempts 
           WHERE ip_address = ? 
           AND attempted_at >= datetime('now', '-10 minutes')""",
        (ip,)
    ).fetchone()['cnt']
    
    if count >= 5:
        # Block the IP
        try:
            conn.execute(
                "INSERT INTO blocked_ips (ip_address, reason) VALUES (?, ?)",
                (ip, f'Too many failed attempts: {count} in 10 minutes')
            )
            conn.commit()
            print(f"IP BLOCKED: {ip} after {count} failed attempts")
        except sqlite3.IntegrityError:
            pass  # already blocked
    
    conn.close()
    return count

# ─── Routes ───────────────────────────────────────────────────────

@auth_bp.route('/register', methods=['POST'])
@jwt_required()
def register():
    """Only admins can register new users"""
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'viewer')  # default role is viewer
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    if role not in ['admin', 'analyst', 'viewer']:
        return jsonify({'error': 'Invalid role. Choose: admin, analyst, viewer'}), 400
    
    # Hash password
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hashed.decode(), role)
        )
        conn.commit()
        conn.close()
        
        log_action(username, 'REGISTER', request.remote_addr, 'SUCCESS')
        return jsonify({'message': f'User {username} created with role {role}'}), 201
    
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409

@auth_bp.route('/login', methods=['POST'])
def login():
    ip = request.remote_addr
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Check if IP is blocked
    if is_ip_blocked(ip):
        log_action(username, 'LOGIN_BLOCKED', ip, 'BLOCKED')
        return jsonify({'error': 'Your IP has been blocked due to too many failed attempts'}), 403
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ? AND is_active = 1", 
        (username,)
    ).fetchone()
    conn.close()
    
    if not user or not bcrypt.checkpw(password.encode(), user['password'].encode()):
        # Track failed attempt
        attempts = check_and_block_ip(ip, username)
        log_action(username, 'LOGIN_FAILED', ip, 'FAILED')
        
        remaining = max(0, 5 - attempts)
        return jsonify({
            'error': 'Invalid credentials',
            'warning': f'{remaining} attempts remaining before IP block'
        }), 401
    
    # Successful login
    access_token = create_access_token(
        identity=username,
        additional_claims={'role': user['role']},
        expires_delta=timedelta(hours=8)
    )
    
    log_action(username, 'LOGIN_SUCCESS', ip, 'SUCCESS')
    
    return jsonify({
        'access_token': access_token,
        'username': username,
        'role': user['role'],
        'message': f'Welcome {username}! Role: {user["role"]}'
    }), 200

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    username = get_jwt_identity()
    log_action(username, 'LOGOUT', request.remote_addr, 'SUCCESS')
    return jsonify({'message': 'Logged out successfully'}), 200

@auth_bp.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    """Only admins can see all users"""
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    conn = get_db()
    users = conn.execute(
        "SELECT id, username, role, created_at, is_active FROM users"
    ).fetchall()
    conn.close()
    
    return jsonify([dict(u) for u in users]), 200

@auth_bp.route('/audit-log', methods=['GET'])
@jwt_required()
def get_audit_log():
    """Admins and analysts can see audit log"""
    claims = get_jwt()
    if claims.get('role') not in ['admin', 'analyst']:
        return jsonify({'error': 'Insufficient permissions'}), 403
    
    conn = get_db()
    logs = conn.execute(
        "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 100"
    ).fetchall()
    conn.close()
    
    return jsonify([dict(l) for l in logs]), 200

@auth_bp.route('/blocked-ips', methods=['GET'])
@jwt_required()
def get_blocked_ips():
    claims = get_jwt()
    if claims.get('role') not in ['admin', 'analyst']:
        return jsonify({'error': 'Insufficient permissions'}), 403
    
    conn = get_db()
    ips = conn.execute("SELECT * FROM blocked_ips").fetchall()
    conn.close()
    return jsonify([dict(ip) for ip in ips]), 200

@auth_bp.route('/unblock-ip', methods=['POST'])
@jwt_required()
def unblock_ip():
    """Only admin can unblock IPs"""
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.get_json()
    ip = data.get('ip_address')
    
    conn = get_db()
    conn.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip,))
    conn.execute("DELETE FROM failed_attempts WHERE ip_address = ?", (ip,))
    conn.commit()
    conn.close()
    
    return jsonify({'message': f'IP {ip} unblocked successfully'}), 200