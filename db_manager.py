import sqlite3
import os
import json
from datetime import date

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "secscan.db")

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    try:
        conn.execute('PRAGMA journal_mode=WAL;')
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            username TEXT UNIQUE NOT NULL, 
            password_hash TEXT NOT NULL, 
            plan TEXT DEFAULT 'free', 
            scans_today INTEGER DEFAULT 0, 
            last_scan_date DATE)''')
            
        cursor.execute('''CREATE TABLE IF NOT EXISTS weights (
            rule_id TEXT PRIMARY KEY, 
            weight REAL DEFAULT 1.0, 
            tp INTEGER DEFAULT 0, 
            fp INTEGER DEFAULT 0)''')
            
        cursor.execute('''CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            username TEXT, 
            filename TEXT, 
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, 
            findings_count INTEGER)''')
            
        cursor.execute('''CREATE TABLE IF NOT EXISTS scan_reports (
            username TEXT PRIMARY KEY, 
            filename TEXT, 
            findings_json TEXT, 
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
            
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_baselines (
            username TEXT, 
            finding_hash TEXT, 
            status TEXT, 
            PRIMARY KEY(username, finding_hash))''')
        
        conn.commit()
    finally:
        conn.close()

def create_user(username, password_hash):
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_user(username):
    conn = get_db()
    try:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    finally:
        conn.close()

def check_and_increment_limit(username):
    conn = get_db()
    try:
        cursor = conn.cursor()
        user = cursor.execute("SELECT scans_today, last_scan_date, plan FROM users WHERE username = ?", (username,)).fetchone()
        if not user: return False, 0
        
        today = date.today().isoformat()
        scans_today = user['scans_today']
        
        if user['last_scan_date'] != today:
            scans_today = 0
            
        limit = 5 if user['plan'] == 'free' else 9999
        
        if scans_today >= limit:
            return False, 0
            
        cursor.execute("UPDATE users SET scans_today = ?, last_scan_date = ? WHERE username = ?", (scans_today + 1, today, username))
        conn.commit()
        return True, limit - (scans_today + 1)
    finally:
        conn.close()

def get_user_scans(username, limit=10):
    conn = get_db()
    try:
        return conn.execute("SELECT filename, timestamp, findings_count FROM scans WHERE username = ? ORDER BY timestamp DESC LIMIT ?", (username, limit)).fetchall()
    finally:
        conn.close()

def upgrade_user_plan(username):
    conn = get_db()
    try:
        conn.execute("UPDATE users SET plan = 'pro' WHERE username = ?", (username,))
        conn.commit()
    finally:
        conn.close()

def save_scan_report(username, filename, findings):
    conn = get_db()
    try:
        findings_json = json.dumps(findings, ensure_ascii=False)
        conn.execute('''INSERT INTO scan_reports (username, filename, findings_json) VALUES (?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET filename=excluded.filename, findings_json=excluded.findings_json, timestamp=CURRENT_TIMESTAMP''', (username, filename, findings_json))
        conn.execute("INSERT INTO scans (username, filename, findings_count) VALUES (?, ?, ?)", (username, filename, len(findings)))
        conn.commit()
    finally:
        conn.close()

def get_last_scan_report(username):
    conn = get_db()
    try:
        row = conn.execute("SELECT filename, findings_json FROM scan_reports WHERE username = ?", (username,)).fetchone()
        if row:
            return row['filename'], json.loads(row['findings_json'])
        return None, None
    finally:
        conn.close()

def get_weight(rule_id):
    conn = get_db()
    try:
        row = conn.execute("SELECT weight FROM weights WHERE rule_id = ?", (rule_id,)).fetchone()
        return row['weight'] if row else 1.0
    finally:
        conn.close()

def update_weight(rule_id, is_tp):
    conn = get_db()
    try:
        cursor = conn.cursor()
        row = cursor.execute("SELECT weight, tp, fp FROM weights WHERE rule_id = ?", (rule_id,)).fetchone()
        current_weight = row['weight'] if row else 1.0
        tp = (row['tp'] if row else 0) + (1 if is_tp else 0)
        fp = (row['fp'] if row else 0) + (0 if is_tp else 1)
        
        new_weight = current_weight + (0.1 * (1.0 - current_weight)) if is_tp else current_weight - (0.1 * current_weight)
        new_weight = round(new_weight, 4)
        
        cursor.execute('''INSERT INTO weights (rule_id, weight, tp, fp) VALUES (?, ?, ?, ?)
            ON CONFLICT(rule_id) DO UPDATE SET weight=excluded.weight, tp=excluded.tp, fp=excluded.fp''', (rule_id, new_weight, tp, fp))
        conn.commit()
        return new_weight
    finally:
        conn.close()

def save_user_baseline(username, finding_hash, status):
    conn = get_db()
    try:
        conn.execute('''INSERT INTO user_baselines (username, finding_hash, status) VALUES (?, ?, ?)
            ON CONFLICT(username, finding_hash) DO UPDATE SET status=excluded.status''', (username, finding_hash, status))
        conn.commit()
    finally:
        conn.close()

def get_user_baselines(username):
    conn = get_db()
    try:
        rows = conn.execute("SELECT finding_hash, status FROM user_baselines WHERE username = ?", (username,)).fetchall()
        return {row['finding_hash']: row['status'] for row in rows}
    finally:
        conn.close()