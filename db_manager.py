import sqlite3
import os
import json
import uuid
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
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, plan TEXT DEFAULT 'free', scans_today INTEGER DEFAULT 0, last_scan_date DATE)''')
        
        cursor.execute("PRAGMA table_info(users)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if 'api_key' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN api_key TEXT")
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_api_key ON users(api_key)")
        if 'webhook_url' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN webhook_url TEXT")
        if 'email' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")
        if 'is_verified' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 1")
        if 'totp_secret' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
        if 'is_admin' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")

        cursor.execute('''CREATE TABLE IF NOT EXISTS api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, api_key TEXT UNIQUE, name TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS weights (rule_id TEXT PRIMARY KEY, weight REAL DEFAULT 1.0, tp INTEGER DEFAULT 0, fp INTEGER DEFAULT 0)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, filename TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, findings_count INTEGER)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS scan_reports (username TEXT PRIMARY KEY, filename TEXT, findings_json TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_baselines (username TEXT, finding_hash TEXT, status TEXT, PRIMARY KEY(username, finding_hash))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS custom_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, rule_id TEXT, severity TEXT, pattern TEXT, message TEXT)''')
        
        # Таблица для SBOM
        cursor.execute('''CREATE TABLE IF NOT EXISTS invite_codes (id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE NOT NULL, plan TEXT DEFAULT 'pro', created_by TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, used_by TEXT, used_at DATETIME, expires_at DATETIME, max_uses INTEGER DEFAULT 1, current_uses INTEGER DEFAULT 0)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS sboms (
            username TEXT PRIMARY KEY, filename TEXT, sbom_json TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        
        conn.commit()
    finally:
        conn.close()

def create_user(username, password_hash, email, is_verified=1, plan='pro'):
    conn = get_db()
    try:
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        is_admin = 1 if count == 0 else 0
        conn.execute("INSERT INTO users (username, password_hash, email, is_verified, plan, is_admin) VALUES (?, ?, ?, ?, ?, ?)", (username, password_hash, email, is_verified, plan, is_admin))
        conn.commit()
        return True
    except sqlite3.IntegrityError: return False
    finally: conn.close()

def verify_user_email(username):
    conn = get_db()
    try:
        conn.execute("UPDATE users SET is_verified = 1 WHERE username = ?", (username,))
        conn.commit()
    finally: conn.close()

def get_user(username):
    conn = get_db()
    try: return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    finally: conn.close()

def update_2fa_secret(username, secret):
    conn = get_db()
    try:
        conn.execute("UPDATE users SET totp_secret = ? WHERE username = ?", (secret, username))
        conn.commit()
    finally: conn.close()

def disable_2fa(username):
    conn = get_db()
    try:
        conn.execute("UPDATE users SET totp_secret = NULL WHERE username = ?", (username,))
        conn.commit()
    finally: conn.close()

def update_user_email(username, new_email):
    conn = get_db()
    try:
        conn.execute("UPDATE users SET email = ?, is_verified = 0 WHERE username = ?", (new_email, username))
        conn.commit()
    finally: conn.close()

def update_user_password(username, new_password_hash):
    conn = get_db()
    try:
        conn.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_password_hash, username))
        conn.commit()
    finally: conn.close()

def get_key_limit(plan):
    if plan == 'free': return 0
    if plan == 'pro': return 1
    if plan == 'startup': return 3
    if plan == 'team': return 5
    return 999

def get_user_api_keys(username):
    conn = get_db()
    try: return conn.execute("SELECT * FROM api_keys WHERE username = ?", (username,)).fetchall()
    finally: conn.close()

def create_api_key(username, name):
    user = get_user(username)
    limit = get_key_limit(user['plan'])
    conn = get_db()
    try:
        count = conn.execute("SELECT COUNT(*) FROM api_keys WHERE username = ?", (username,)).fetchone()[0]
        if count >= limit: return None, f"Достигнут лимит ключей для тарифа {user['plan'].upper()} ({limit})"
        new_key = "sec_" + uuid.uuid4().hex
        conn.execute("INSERT INTO api_keys (username, api_key, name) VALUES (?, ?, ?)", (username, new_key, name))
        conn.commit()
        return new_key, None
    finally: conn.close()

def delete_api_key(key_id, username):
    conn = get_db()
    try:
        conn.execute("DELETE FROM api_keys WHERE id = ? AND username = ?", (key_id, username))
        conn.commit()
    finally: conn.close()

def get_user_by_api_key(api_key):
    conn = get_db()
    try: 
        key_row = conn.execute("SELECT username FROM api_keys WHERE api_key = ?", (api_key,)).fetchone()
        if not key_row: return None
        return conn.execute("SELECT * FROM users WHERE username = ?", (key_row['username'],)).fetchone()
    finally: conn.close()

def set_webhook(username, url):
    conn = get_db()
    try:
        conn.execute("UPDATE users SET webhook_url = ? WHERE username = ?", (url, username))
        conn.commit()
    finally: conn.close()

def check_and_increment_limit(username):
    conn = get_db()
    try:
        cursor = conn.cursor()
        user = cursor.execute("SELECT scans_today, last_scan_date, plan FROM users WHERE username = ?", (username,)).fetchone()
        if not user: return False, 0
        today = date.today().isoformat()
        scans_today = user['scans_today'] or 0
        if user['last_scan_date'] != today: scans_today = 0
        limit = 5 if user['plan'] == 'free' else 9999
        if scans_today >= limit: return False, 0
        cursor.execute("UPDATE users SET scans_today = ?, last_scan_date = ? WHERE username = ?", (scans_today + 1, today, username))
        conn.commit()
        return True, limit - (scans_today + 1)
    finally: conn.close()

def get_user_scans(username, limit=10):
    conn = get_db()
    try: return conn.execute("SELECT filename, timestamp, findings_count FROM scans WHERE username = ? ORDER BY timestamp DESC LIMIT ?", (username, limit)).fetchall()
    finally: conn.close()

def get_user_stats(username):
    conn = get_db()
    try:
        total_scans = conn.execute("SELECT COUNT(*) FROM scans WHERE username = ?", (username,)).fetchone()[0]
        total_issues = conn.execute("SELECT SUM(findings_count) FROM scans WHERE username = ?", (username,)).fetchone()[0]
        return {"total_scans": total_scans, "total_issues": total_issues or 0}
    finally: conn.close()

def change_user_plan(username, new_plan):
    conn = get_db()
    try:
        conn.execute("UPDATE users SET plan = ? WHERE username = ?", (new_plan, username))
        conn.commit()
    finally:
        conn.close()

def upgrade_user_plan(username):
    conn = get_db()
    try:
        conn.execute("UPDATE users SET plan = 'pro' WHERE username = ?", (username,))
        conn.commit()
    finally: conn.close()

def save_scan_report(username, filename, findings):
    conn = get_db()
    try:
        findings_json = json.dumps(findings, ensure_ascii=False)
        conn.execute('''INSERT INTO scan_reports (username, filename, findings_json) VALUES (?, 'Anonymous Project', ?) ON CONFLICT(username) DO UPDATE SET filename=excluded.filename, findings_json=excluded.findings_json, timestamp=CURRENT_TIMESTAMP''', (username, findings_json))
        conn.execute("INSERT INTO scans (username, filename, findings_count) VALUES (?, ?, ?)", (username, 'Anonymous Project', len(findings)))
        conn.commit()
    finally: conn.close()

def get_last_scan_report(username):
    conn = get_db()
    try:
        row = conn.execute("SELECT filename, findings_json FROM scan_reports WHERE username = ?", (username,)).fetchone()
        if row: return row['filename'], json.loads(row['findings_json'])
        return None, None
    finally: conn.close()

def get_weight(rule_id):
    conn = get_db()
    try:
        row = conn.execute("SELECT weight FROM weights WHERE rule_id = ?", (rule_id,)).fetchone()
        return row['weight'] if row else 1.0
    finally: conn.close()

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
        cursor.execute('''INSERT INTO weights (rule_id, weight, tp, fp) VALUES (?, ?, ?, ?) ON CONFLICT(rule_id) DO UPDATE SET weight=excluded.weight, tp=excluded.tp, fp=excluded.fp''', (rule_id, new_weight, tp, fp))
        conn.commit()
        return new_weight
    finally: conn.close()

def save_user_baseline(username, finding_hash, status):
    conn = get_db()
    try:
        conn.execute('''INSERT INTO user_baselines (username, finding_hash, status) VALUES (?, ?, ?) ON CONFLICT(username, finding_hash) DO UPDATE SET status=excluded.status''', (username, finding_hash, status))
        conn.commit()
    finally: conn.close()

def get_user_baselines(username):
    conn = get_db()
    try:
        rows = conn.execute("SELECT finding_hash, status FROM user_baselines WHERE username = ?", (username,)).fetchall()
        return {row['finding_hash']: row['status'] for row in rows}
    finally: conn.close()

def get_custom_rules(username):
    conn = get_db()
    try: return conn.execute("SELECT * FROM custom_rules WHERE username = ?", (username,)).fetchall()
    finally: conn.close()

def add_custom_rule(username, rule_id, severity, pattern, message):
    conn = get_db()
    try:
        conn.execute("INSERT INTO custom_rules (username, rule_id, severity, pattern, message) VALUES (?, ?, ?, ?, ?)", (username, rule_id, severity, pattern, message))
        conn.commit()
    finally: conn.close()

def delete_custom_rule(rule_id, username):
    conn = get_db()
    try:
        conn.execute("DELETE FROM custom_rules WHERE id = ? AND username = ?", (rule_id, username))
        conn.commit()
    finally: conn.close()

def save_sbom(username, filename, sbom_json):
    conn = get_db()
    try:
        conn.execute('''INSERT INTO sboms (username, filename, sbom_json) VALUES (?, ?, ?) 
            ON CONFLICT(username) DO UPDATE SET filename=excluded.filename, sbom_json=excluded.sbom_json, timestamp=CURRENT_TIMESTAMP''', 
            (username, filename, sbom_json))
        conn.commit()
    finally: conn.close()

def get_last_sbom(username):
    conn = get_db()
    try:
        row = conn.execute("SELECT filename, sbom_json FROM sboms WHERE username = ?", (username,)).fetchone()
        if row: return row['filename'], row['sbom_json']
        return None, None
    finally: conn.close()

# ============ ADMIN & INVITE FUNCTIONS ============
import uuid as _uuid
from datetime import datetime as _dt, timedelta as _td

def is_admin(username):
    u = get_user(username)
    return bool(u and u['is_admin'])

def get_all_users():
    conn = get_db()
    try:
        return conn.execute("SELECT id, username, email, plan, is_verified, is_admin, scans_today FROM users ORDER BY id").fetchall()
    finally:
        conn.close()

def admin_update_user(username, field, value):
    if field not in ['plan', 'is_verified', 'is_admin']:
        return False
    conn = get_db()
    try:
        conn.execute(f"UPDATE users SET {field} = ? WHERE username = ?", (value, username))
        conn.commit()
        return True
    finally:
        conn.close()

def admin_delete_user(username):
    conn = get_db()
    try:
        for table in ['users', 'scans', 'scan_reports', 'api_keys', 'user_baselines', 'custom_rules', 'sboms']:
            try:
                conn.execute(f"DELETE FROM {table} WHERE username = ?", (username,))
            except: pass
        conn.commit()
        return True
    finally:
        conn.close()

def admin_reset_password(username, new_hash):
    conn = get_db()
    try:
        conn.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_hash, username))
        conn.commit()
        return True
    finally:
        conn.close()

def create_invite(created_by, plan='pro', max_uses=1, days=7):
    code = "INV-" + _uuid.uuid4().hex[:12].upper()
    expires = (_dt.now() + _td(days=days)).isoformat()
    conn = get_db()
    try:
        conn.execute("INSERT INTO invite_codes (code, plan, created_by, max_uses, expires_at) VALUES (?, ?, ?, ?, ?)", (code, plan, created_by, max_uses, expires))
        conn.commit()
        return code
    finally:
        conn.close()

def validate_invite(code):
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM invite_codes WHERE code = ?", (code,)).fetchone()
        if not row: return None
        if row['current_uses'] >= row['max_uses']: return None
        if row['expires_at'] and _dt.fromisoformat(row['expires_at']) < _dt.now(): return None
        return row
    finally:
        conn.close()

def use_invite(code, username):
    conn = get_db()
    try:
        conn.execute("UPDATE invite_codes SET current_uses = current_uses + 1, used_by = ?, used_at = CURRENT_TIMESTAMP WHERE code = ?", (username, code))
        conn.commit()
    finally:
        conn.close()

def get_all_invites():
    conn = get_db()
    try:
        return conn.execute("SELECT * FROM invite_codes ORDER BY created_at DESC").fetchall()
    finally:
        conn.close()

def delete_invite(invite_id):
    conn = get_db()
    try:
        conn.execute("DELETE FROM invite_codes WHERE id = ?", (invite_id,))
        conn.commit()
    finally:
        conn.close()
