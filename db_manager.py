import sqlite3
import os
import json
import uuid
from datetime import date

# ============ POSTGRES ADAPTER ============
import os as _os

try:
    import psycopg2 as _psycopg2
    import psycopg2.extras as _psycopg2_extras
    _PG_AVAILABLE = True
except ImportError:
    _psycopg2 = None
    _psycopg2_extras = None
    _PG_AVAILABLE = False

_USE_POSTGRES = _os.environ.get("USE_POSTGRES", "false").lower() in ("1", "true", "yes") and _PG_AVAILABLE
if _os.environ.get("USE_POSTGRES", "false").lower() in ("1", "true", "yes") and not _PG_AVAILABLE:
    print("[db] WARNING: USE_POSTGRES=true but psycopg2 not installed; falling back to SQLite", flush=True)


def _convert_query(q):
    """Convert ? placeholders to %s (escape literal % first)."""
    return q.replace("%", "%%").replace("?", "%s")


class _PGCursor:
    def __init__(self, pg_cur):
        self._c = pg_cur

    def execute(self, q, p=()):
        self._c.execute(_convert_query(q), p)
        return self

    def fetchone(self):
        return self._c.fetchone()

    def fetchall(self):
        return self._c.fetchall()

    def close(self):
        self._c.close()


class _PGConnection:
    def __init__(self, pg_conn):
        self._c = pg_conn

    def execute(self, q, p=()):
        cur = self._c.cursor(cursor_factory=_psycopg2_extras.DictCursor)
        try:
            cur.execute(_convert_query(q), p)
        except _psycopg2.IntegrityError as e:
            raise sqlite3.IntegrityError(str(e))
        return cur

    def cursor(self):
        cur = self._c.cursor(cursor_factory=_psycopg2_extras.DictCursor)
        return _PGCursor(cur)

    def commit(self):
        self._c.commit()

    def close(self):
        self._c.close()


def _get_db_postgres():
    conn = _psycopg2.connect(
        host=_os.environ.get("POSTGRES_HOST", "postgres"),
        port=int(_os.environ.get("POSTGRES_PORT", "5432")),
        user=_os.environ.get("POSTGRES_USER"),
        password=_os.environ.get("POSTGRES_PASSWORD"),
        dbname=_os.environ.get("POSTGRES_DB"),
        connect_timeout=10,
    )
    return _PGConnection(conn)
# ============ END POSTGRES ADAPTER ============


DB_PATH = os.path.join(os.path.dirname(__file__), "data", "secscan.db")

def get_db():
    if _USE_POSTGRES:
        return _get_db_postgres()
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if _USE_POSTGRES:
        return _init_db_postgres()
    return _init_db_sqlite()


def _init_db_postgres():
    conn = _get_db_postgres()
    try:
        cur = conn._c.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS users (id BIGSERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, plan TEXT DEFAULT 'free', scans_today INTEGER DEFAULT 0, last_scan_date DATE, api_key TEXT, webhook_url TEXT, email TEXT, is_verified INTEGER DEFAULT 1, totp_secret TEXT, is_admin INTEGER DEFAULT 0, credits INTEGER DEFAULT 0, ref_code TEXT, referred_by TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_api_key ON users(api_key)")
        cur.execute("CREATE TABLE IF NOT EXISTS api_keys (id BIGSERIAL PRIMARY KEY, username TEXT, api_key TEXT UNIQUE, name TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        cur.execute("CREATE TABLE IF NOT EXISTS weights (rule_id TEXT PRIMARY KEY, weight REAL DEFAULT 1.0, tp INTEGER DEFAULT 0, fp INTEGER DEFAULT 0)")
        cur.execute("CREATE TABLE IF NOT EXISTS scans (id BIGSERIAL PRIMARY KEY, username TEXT, filename TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, findings_count INTEGER)")
        cur.execute("CREATE TABLE IF NOT EXISTS scan_reports (username TEXT PRIMARY KEY, filename TEXT, findings_json TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        cur.execute("CREATE TABLE IF NOT EXISTS user_baselines (username TEXT, finding_hash TEXT, status TEXT, PRIMARY KEY(username, finding_hash))")
        cur.execute("CREATE TABLE IF NOT EXISTS custom_rules (id BIGSERIAL PRIMARY KEY, username TEXT, rule_id TEXT, severity TEXT, pattern TEXT, message TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS invite_codes (id BIGSERIAL PRIMARY KEY, code TEXT UNIQUE NOT NULL, plan TEXT DEFAULT 'pro', created_by TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, used_by TEXT, used_at TIMESTAMP, expires_at TIMESTAMP, max_uses INTEGER DEFAULT 1, current_uses INTEGER DEFAULT 0)")
        cur.execute("CREATE TABLE IF NOT EXISTS sboms (username TEXT PRIMARY KEY, filename TEXT, sbom_json TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        cur.execute("CREATE TABLE IF NOT EXISTS audit_log (id BIGSERIAL PRIMARY KEY, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, username TEXT, action TEXT NOT NULL, target TEXT, details TEXT, ip_address TEXT, user_agent TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS credit_transactions (id BIGSERIAL PRIMARY KEY, username TEXT, amount INTEGER, reason TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        cur.execute("CREATE TABLE IF NOT EXISTS organizations (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, owner_username TEXT NOT NULL, plan TEXT DEFAULT 'team', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        cur.execute("CREATE TABLE IF NOT EXISTS org_members (org_id BIGINT, username TEXT, role TEXT DEFAULT 'scanner', joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(org_id, username))")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_org_members_username ON org_members(username)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_log(username)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)")
        conn.commit()
        cur.close()
        print("[db] Postgres schema initialized", flush=True)
    finally:
        conn.close()


def _init_db_sqlite():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    try:
        conn.execute('PRAGMA journal_mode=WAL;')
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, plan TEXT DEFAULT 'free', scans_today INTEGER DEFAULT 0, last_scan_date DATE, credits INTEGER DEFAULT 0)''')
        
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
        cursor.execute("CREATE TABLE IF NOT EXISTS credit_transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, amount INTEGER, reason TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
        cursor.execute('''CREATE TABLE IF NOT EXISTS invite_codes (id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE NOT NULL, plan TEXT DEFAULT 'pro', created_by TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, used_by TEXT, used_at DATETIME, expires_at DATETIME, max_uses INTEGER DEFAULT 1, current_uses INTEGER DEFAULT 0)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS sboms (
            username TEXT PRIMARY KEY, filename TEXT, sbom_json TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        
        cursor.execute("CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, username TEXT, action TEXT NOT NULL, target TEXT, details TEXT, ip_address TEXT, user_agent TEXT)")
        cursor.execute("CREATE TABLE IF NOT EXISTS organizations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, owner_username TEXT NOT NULL, plan TEXT DEFAULT 'team', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
        cursor.execute("CREATE TABLE IF NOT EXISTS org_members (org_id INTEGER, username TEXT, role TEXT DEFAULT 'scanner', joined_at DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(org_id, username))")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_org_members_username ON org_members(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_log(username)")

        conn.commit()
    finally:
        conn.close()

def create_user(username, password_hash, email, is_verified=1, plan='pro', referred_by=None):
    import uuid
    conn = get_db()
    try:
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        is_admin = 1 if count == 0 else 0
        ref_code = f"{username[:4].lower()}{uuid.uuid4().hex[:4]}"
        
        conn.execute("INSERT INTO users (username, password_hash, email, is_verified, plan, is_admin, ref_code, referred_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", 
                     (username, password_hash, email, is_verified, plan, is_admin, ref_code, referred_by))
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

def get_user_by_email(email):
    conn = get_db()
    try:
        return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    finally:
        conn.close()


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
    """Variant B: no daily limit. Each scan costs 1 credit.
    Pro / Free — pay-per-credit. Startup/Team/Enterprise — unlimited."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        user = cursor.execute("SELECT plan, credits FROM users WHERE username = ?", (username,)).fetchone()
        if not user: return False, 0

        # Бизнес-тарифы (Startup/Team/Enterprise) — безлимит
        if user['plan'] in ('startup', 'team', 'enterprise'):
            return True, 9999

        # Free и Pro: каждый скан списывает 1 кредит
        credits = user['credits'] or 0
        if credits > 0:
            cursor.execute("UPDATE users SET credits = credits - 1 WHERE username = ?", (username,))
            cursor.execute("INSERT INTO credit_transactions (username, amount, reason) VALUES (?, ?, ?)", (username, -1, 'scan'))
            conn.commit()
            return True, credits - 1
        return False, 0
    finally:
        conn.close()

def add_credits(username, amount, reason='purchase'):
    conn = get_db()
    try:
        conn.execute("UPDATE users SET credits = credits + ? WHERE username = ?", (amount, username))
        conn.execute("INSERT INTO credit_transactions (username, amount, reason) VALUES (?, ?, ?)", (username, amount, reason))
        conn.commit()
        return True
    except Exception as e:
        print(f"[CREDITS] Error: {e}", flush=True)
        return False
    finally:
        conn.close()

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

def get_user_trend(username):
    """Возвращает список {'date': 'YYYY-MM-DD', 'count': N} для графика."""
    conn = get_db()
    try:
        rows = conn.execute("SELECT timestamp, findings_count FROM scans WHERE username = ? ORDER BY timestamp ASC", (username,)).fetchall()
        trend = {}
        for r in rows:
            ts = r['timestamp']
            # Postgres возвращает datetime, SQLite - строку
            if hasattr(ts, 'strftime'):
                d = ts.strftime('%Y-%m-%d')
            else:
                d = str(ts)[:10]
            trend[d] = trend.get(d, 0) + (r['findings_count'] or 0)
        return [{"date": k, "count": v} for k, v in trend.items()]
    finally:
        conn.close()


def change_user_plan(username, new_plan):
    """Смена тарифа. При переходе на Pro начисляет 100 кредитов (единоразово)."""
    conn = get_db()
    try:
        old = conn.execute("SELECT plan FROM users WHERE username = ?", (username,)).fetchone()
        old_plan = old['plan'] if old else None
        
        conn.execute("UPDATE users SET plan = ? WHERE username = ?", (new_plan, username))
        conn.commit()
        
        # Если перешли на Pro — начисляем 100 кредитов (только если это новый переход)
        if new_plan == 'pro' and old_plan != 'pro':
            add_credits(username, 100, 'pro_plan_monthly')
            print(f"[PLAN] {username}: +100 credits for Pro plan", flush=True)
    finally:
        conn.close()

def upgrade_user_plan(username):
    conn = get_db()
    try:
        conn.execute("UPDATE users SET plan = 'pro' WHERE username = ?", (username,))
        conn.commit()
        add_credits(username, 100, 'pro_plan_upgrade')
        print(f"[PLAN] {username}: +100 credits for Pro upgrade", flush=True)
    finally: conn.close()

def save_scan_report(username, filename, findings):
    user = get_user(username)
    stored_name = "Anonymous Project"
    if user and user['plan'] != 'free':
        stored_name = filename or "Unnamed Project"
    conn = get_db()
    try:
        findings_json = json.dumps(findings, ensure_ascii=False)
        conn.execute('''INSERT INTO scan_reports (username, filename, findings_json) VALUES (?, ?, ?) ON CONFLICT(username) DO UPDATE SET filename=excluded.filename, findings_json=excluded.findings_json, timestamp=CURRENT_TIMESTAMP''', (username, stored_name, findings_json))
        conn.execute("INSERT INTO scans (username, filename, findings_count) VALUES (?, ?, ?)", (username, stored_name, len(findings)))
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

def create_invite(created_by, plan='pro', max_uses=1, days=7, org_id=None, email=None):
    code = "INV-" + _uuid.uuid4().hex[:12].upper()
    expires = (_dt.now() + _td(days=days)).isoformat()
    conn = get_db()
    try:
        conn.execute("INSERT INTO invite_codes (code, plan, created_by, max_uses, expires_at, org_id, email) VALUES (?, ?, ?, ?, ?, ?, ?)", (code, plan, created_by, max_uses, expires, org_id, email))
        conn.commit()
        return code
    finally:
        conn.close()

def get_invite(code):
    conn = get_db()
    try:
        return conn.execute("SELECT * FROM invite_codes WHERE code = ?", (code,)).fetchone()
    finally:
        conn.close()

def validate_invite(code):
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM invite_codes WHERE code = ?", (code,)).fetchone()
        if not row: return None
        if row['current_uses'] >= row['max_uses']: return None
        
        # Postgres возвращает datetime, SQLite - строку. Обрабатываем оба.
        exp = row['expires_at']
        if exp:
            if isinstance(exp, str):
                try:
                    exp_dt = _dt.fromisoformat(exp)
                except Exception:
                    exp_dt = None
            else:
                exp_dt = exp
            
            if exp_dt and exp_dt < _dt.now():
                return None
        
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


# ============ AUDIT LOG ============
def log_action(username, action, target=None, details=None, ip=None, ua=None):
    """Записать действие в audit_log. Никогда не бросает исключение (логирование не должно ломать запрос)."""
    try:
        conn = get_db()
        try:
            details_str = json.dumps(details, ensure_ascii=False) if details is not None else None
            ua_trunc = (ua[:500] if ua else None)
            conn.execute(
                "INSERT INTO audit_log (username, action, target, details, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
                (username or "anonymous", action, target, details_str, ip, ua_trunc),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"[audit] log_action failed: {e}", flush=True)


def get_audit_log(username=None, action=None, limit=100, offset=0):
    """Вернуть записи audit_log с фильтрами."""
    conn = get_db()
    try:
        q = "SELECT id, timestamp, username, action, target, details, ip_address, user_agent FROM audit_log WHERE 1=1"
        params = []
        if username:
            q += " AND username = ?"
            params.append(username)
        if action:
            q += " AND action LIKE ?"
            params.append(f"{action}%")
        q += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([int(limit), int(offset)])
        return conn.execute(q, params).fetchall()
    finally:
        conn.close()


def get_audit_actions():
    """Уникальные actions для dropdown-фильтра."""
    conn = get_db()
    try:
        rows = conn.execute("SELECT DISTINCT action FROM audit_log ORDER BY action").fetchall()
        return [r["action"] for r in rows]
    finally:
        conn.close()


def get_audit_count(username=None, action=None):
    conn = get_db()
    try:
        q = "SELECT COUNT(*) FROM audit_log WHERE 1=1"
        params = []
        if username:
            q += " AND username = ?"
            params.append(username)
        if action:
            q += " AND action LIKE ?"
            params.append(f"{action}%")
        return conn.execute(q, params).fetchone()[0]
    finally:
        conn.close()


# ============ ORGANIZATIONS ============
def create_organization(name, owner_username, plan='team'):
    """Создать организацию. Владелец автоматически добавляется как owner."""
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO organizations (name, owner_username, plan) VALUES (?, ?, ?)",
            (name, owner_username, plan),
        )
        conn.commit()
        # Получаем org_id (для Postgres — RETURNING, для SQLite — lastrowid)
        if hasattr(cur, 'lastrowid') and cur.lastrowid:
            org_id = cur.lastrowid
        else:
            # Postgres: SELECT по owner_username + name (свежая запись)
            row = conn.execute(
                "SELECT id FROM organizations WHERE owner_username = ? AND name = ? ORDER BY id DESC LIMIT 1",
                (owner_username, name),
            ).fetchone()
            org_id = row['id'] if row else None
        if org_id:
            conn.execute(
                "INSERT INTO org_members (org_id, username, role) VALUES (?, ?, 'owner')",
                (org_id, owner_username),
            )
            conn.commit()
        return org_id
    finally:
        conn.close()


def get_organization(org_id):
    conn = get_db()
    try:
        return conn.execute("SELECT * FROM organizations WHERE id = ?", (org_id,)).fetchone()
    finally:
        conn.close()


def get_user_orgs(username):
    """Список организаций, в которых пользователь — член (с ролью)."""
    conn = get_db()
    try:
        q = """SELECT o.id, o.name, o.owner_username, o.plan, o.created_at, m.role
               FROM organizations o
               JOIN org_members m ON m.org_id = o.id
               WHERE m.username = ?
               ORDER BY o.id"""
        return conn.execute(q, (username,)).fetchall()
    finally:
        conn.close()


def add_org_member(org_id, username, role='scanner'):
    """Добавить пользователя в организацию."""
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO org_members (org_id, username, role) VALUES (?, ?, ?) ON CONFLICT(org_id, username) DO UPDATE SET role=excluded.role",
            (org_id, username, role),
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"[org] add_member failed: {e}", flush=True)
        return False
    finally:
        conn.close()


def remove_org_member(org_id, username):
    """Удалить пользователя из организации (не owner'а)."""
    conn = get_db()
    try:
        conn.execute(
            "DELETE FROM org_members WHERE org_id = ? AND username = ? AND role != 'owner'",
            (org_id, username),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def get_org_members(org_id):
    """Список членов организации (username, role, email, joined_at)."""
    conn = get_db()
    try:
        q = """SELECT m.username, m.role, m.joined_at, u.email, u.plan
               FROM org_members m
               LEFT JOIN users u ON u.username = m.username
               WHERE m.org_id = ?
               ORDER BY
                 CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 WHEN 'scanner' THEN 2 ELSE 3 END,
                 m.username"""
        return conn.execute(q, (org_id,)).fetchall()
    finally:
        conn.close()


def get_user_role_in_org(org_id, username):
    """Вернуть роль пользователя в организации или None."""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT role FROM org_members WHERE org_id = ? AND username = ?",
            (org_id, username),
        ).fetchone()
        return row['role'] if row else None
    finally:
        conn.close()


def is_org_admin(org_id, username):
    """True, если пользователь — owner или admin организации."""
    role = get_user_role_in_org(org_id, username)
    return role in ('owner', 'admin')


def get_user_by_ref_code(ref_code):
    conn = get_db()
    try:
        return conn.execute("SELECT * FROM users WHERE ref_code = ?", (ref_code,)).fetchone()
    finally:
        conn.close()

def get_referral_stats(username):
    conn = get_db()
    try:
        invited = conn.execute("SELECT COUNT(*) FROM users WHERE referred_by = ?", (username,)).fetchone()[0]
        earned = conn.execute("SELECT SUM(amount) FROM credit_transactions WHERE username = ? AND (reason LIKE 'referral_bonus_for_%' OR reason LIKE 'referral_purchase_bonus_%')", (username,)).fetchone()[0]
        users = conn.execute("SELECT username, created_at FROM users WHERE referred_by = ? ORDER BY id DESC", (username,)).fetchall()
        
        return {
            "invited_count": invited,
            "earned_credits": earned or 0,
            "users": [dict(u) for u in users]
        }
    finally:
        conn.close()


# ============ PAYMENTS ============
def create_payment_record(username, package, amount_credits, amount_byn, provider, provider_order_id):
    conn = get_db()
    try:
        conn.execute("""INSERT INTO payments (username, package, amount_credits, amount_byn, provider, provider_order_id, status)
                        VALUES (?, ?, ?, ?, ?, ?, 'pending')""", 
                     (username, package, amount_credits, amount_byn, provider, provider_order_id))
        conn.commit()
        return True
    except Exception as e:
        print(f"[PAYMENT DB] Error: {e}", flush=True)
        return False
    finally:
        conn.close()

def get_payment_record(provider_order_id):
    conn = get_db()
    try:
        return conn.execute("SELECT * FROM payments WHERE provider_order_id = ?", (provider_order_id,)).fetchone()
    finally:
        conn.close()

def mark_payment_paid(provider_order_id):
    conn = get_db()
    try:
        conn.execute("UPDATE payments SET status = 'paid', paid_at = CURRENT_TIMESTAMP WHERE provider_order_id = ?", (provider_order_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"[PAYMENT DB] Error marking paid: {e}", flush=True)
        return False
    finally:
        conn.close()
