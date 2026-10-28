import os
import re
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import zipfile
import tempfile
import shutil
import requests
import pyotp
import qrcode
import io
import base64
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, Response, stream_with_context
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flasgger import Swagger
from scanner.engine import SecurityScanner
from scanner.sca_engine import SCAEngine
from scanner.ai_engine import AIEngine
from report_generator import ReportGenerator
from sbom_generator import SBOMGenerator
import db_manager
import scan_core
from translations import TRANSLATIONS

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)


app.secret_key = 'super_secret_key_for_dev' 
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

swagger = Swagger(app, template={'info': {'title': 'AI-SecScan API', 'description': 'API для сканирования кода', 'version': '1.0.0'}})

import os as _os
_redis_url = _os.environ.get("REDIS_URL", "redis://redis:6379/0")
try:
    import redis as _redis_mod
    _redis_client = _redis_mod.Redis.from_url(_redis_url, socket_connect_timeout=2, socket_timeout=2)
    _redis_client.ping()
    _limiter_storage = _redis_url
    print(f"[limiter] Using Redis storage: {_redis_url}", flush=True)
except Exception as _e:
    _limiter_storage = "memory://"
    print(f"[limiter] Redis unavailable ({_e}), falling back to memory://", flush=True)
limiter = Limiter(get_remote_address, app=app, default_limits=["10000 per day", "1000 per hour"], storage_uri=_limiter_storage)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(BASE_DIR, "scanner", "rules.json")
CVE_FILE = os.path.join(BASE_DIR, "scanner", "cve_db.json")

db_manager.init_db()
scanner = SecurityScanner(RULES_FILE)
sca_scanner = SCAEngine(CVE_FILE)
ai_scanner = AIEngine()

@app.context_processor
def inject_translations():
    lang = session.get('lang', 'ru')
    def t(key):
        return TRANSLATIONS.get(lang, TRANSLATIONS['en']).get(key, key)
    return dict(t=t, current_lang=lang)

@app.route('/set_lang/<lang_code>')
def set_lang(lang_code):
    if lang_code in ['ru', 'en', 'zh']: session['lang'] = lang_code
    return redirect(request.referrer or url_for('index'))

def safe_extract_zip(zip_path, extract_dir):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.infolist():
            if member.filename.startswith('/') or '..' in member.filename: continue
            zip_ref.extract(member, extract_dir)

def calculate_score(findings):
    score = 100
    for f in findings:
        if "error" in f: continue
        if f.get('severity') == 'CRITICAL': score -= 25
        elif f.get('severity') == 'HIGH': score -= 10
        elif f.get('severity') == 'MEDIUM': score -= 5
    score = max(0, score)
    grade = 'A' if score >= 90 else 'B' if score >= 80 else 'C' if score >= 70 else 'D' if score >= 60 else 'F'
    return score, grade

@app.errorhandler(500)
def internal_error(error): return render_template('500.html'), 500

@app.route('/')
def index():
    if 'username' not in session: return render_template('landing.html')
    return redirect(url_for('profile'))

@app.route('/demo')
def demo():
    session['username'] = 'demo_user'
    return redirect(url_for('profile'))

@app.route('/presentation')
def presentation():
    return render_template('presentation.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/profile')

def profile():
    if 'username' not in session: return redirect(url_for('login'))
    user = db_manager.get_user(session['username'])
    if not user: session.clear(); return redirect(url_for('login'))
    history = db_manager.get_user_scans(session['username'])
    stats = db_manager.get_user_stats(session['username'])
    custom_rules = db_manager.get_custom_rules(session['username'])
    user_api_keys = db_manager.get_user_api_keys(session['username'])
    # SEC 05: Маскируем API-ключи перед передачей в HTML
    masked_keys = []
    for k in user_api_keys:
        kd = dict(k)
        raw = kd.get('api_key', '')
        if raw and len(raw) > 12:
            kd['api_key_masked'] = raw[:8] + '...' + raw[-4:]
        else:
            kd['api_key_masked'] = raw
        masked_keys.append(kd)

    return render_template('profile.html', user=user, history=history, stats=stats, custom_rules=custom_rules, user_api_keys=masked_keys)

@app.route('/upgrade', methods=['POST'])
def upgrade():
    if 'username' in session:
        db_manager.upgrade_user_plan(session['username'])
        flash('Поздравляем! Вы перешли на тариф Pro.')
    return redirect(url_for('profile'))


# --- НАСТРОЙКИ SENDPULSE SMTP ---
SMTP_HOST = "mails.aisecscan.by"
SMTP_PORT = 587
SMTP_LOGIN = "no-reply@aisecscan.by"
SMTP_PASSWORD = "_UQk)tjR87Zn"
FROM_EMAIL = "info@aisecscan.by"

# --- SENDPULSE HTTP API (порт 443) ---
SENDPULSE_CLIENT_ID = os.environ.get("SENDPULSE_CLIENT_ID", "")
SENDPULSE_CLIENT_SECRET = os.environ.get("SENDPULSE_CLIENT_SECRET", "")
DOMAIN_URL = "https://aisecscan.by"


def audit(action, target=None, details=None, username_override=None):
    """Удобная обёртка: берёт username из session, IP и UA из request."""
    try:
        u = username_override or session.get('username') or 'anonymous'
        ip = None
        ua = None
        try:
            ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if ip and ',' in ip:
                ip = ip.split(',')[0].strip()
            ua = request.headers.get('User-Agent', '')[:500]
        except Exception:
            pass
        db_manager.log_action(u, action, target=target, details=details, ip=ip, ua=ua)
    except Exception as e:
        print(f"[audit] wrapper failed: {e}", flush=True)

def _get_redis_for_email():
    """Возвращает Redis-клиент или None, если недоступен."""
    try:
        import redis
        url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
        r = redis.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=2)
        r.ping()
        return r
    except Exception:
        return None


def _get_sendpulse_token():
    """Получает access_token из кэша Redis или запрашивает новый у SendPulse."""
    r = _get_redis_for_email()
    cache_key = "sendpulse:access_token"
    if r:
        cached = r.get(cache_key)
        if cached:
            return cached.decode() if isinstance(cached, bytes) else cached

    resp = requests.post(
        "https://api.sendpulse.com/oauth/access_token",
        json={
            "grant_type": "client_credentials",
            "client_id": SENDPULSE_CLIENT_ID,
            "client_secret": SENDPULSE_CLIENT_SECRET,
        },
        timeout=10,
    )
    resp.raise_for_status()
    token = resp.json()["access_token"]
    if r:
        r.setex(cache_key, 3500, token)  # ~58 минут
    return token


def send_email_via_sendpulse(to_email, subject, body_text):
    """Отправляет письмо через SendPulse HTTP API (порт 443)."""
    token = _get_sendpulse_token()
    payload = {
        "email": {
            "subject": subject,
            "from": {"name": "AI-SecScan", "email": "no-reply@aisecscan.by"},
            "to": [{"name": "", "email": to_email}],
            "text": body_text,
        }
    }
    resp = requests.post(
        "https://api.sendpulse.com/smtp/emails",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=15,
    )
    if resp.status_code >= 400:
        raise Exception(f"SendPulse API {resp.status_code}: {resp.text}")
    return resp.json()


def send_email_async(to_email, subject, body_text):
    """Асинхронная отправка: сначала SendPulse API, при ошибке — SMTP fallback."""
    def _send():
        # 1) SendPulse HTTP API
        if SENDPULSE_CLIENT_ID and SENDPULSE_CLIENT_SECRET:
            try:
                send_email_via_sendpulse(to_email, subject, body_text)
                print(f"[EMAIL SUCCESS] SendPulse API -> {to_email}", flush=True)
                return
            except Exception as e:
                print(f"[EMAIL ERROR] SendPulse API: {e}", flush=True)

        # 2) SMTP fallback
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            msg = MIMEMultipart()
            msg["From"] = "AI-SecScan <no-reply@aisecscan.by>"
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(body_text, "plain", "utf-8"))
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                server.starttls()
                server.login(SMTP_LOGIN, SMTP_PASSWORD)
                server.send_message(msg)
            print(f"[EMAIL SUCCESS] SMTP fallback -> {to_email}", flush=True)
        except Exception as e:
            print(f"[EMAIL ERROR] SMTP fallback: {e}", flush=True)

    threading.Thread(target=_send, daemon=True).start()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        invite_code = request.form.get('invite_code', '').strip()
        
        plan = 'free'
        if invite_code:
            code_data = db_manager.validate_invite(invite_code)
            if not code_data:
                return render_template('register.html', error="Неверный или просроченный код приглашения.")
            plan = code_data['plan']
        
        # Обработка реферального кода
        ref_code = request.args.get('ref') or request.form.get('ref_code', '')
        referrer = db_manager.get_user_by_ref_code(ref_code) if ref_code else None
        referrer_username = referrer['username'] if referrer else None

        if db_manager.create_user(username, generate_password_hash(password), email, 0, plan, referred_by=referrer_username):
            
            # Гибридная логика (Вариант C):
            # - Всем новым юзерам: +3 кредита (welcome bonus)
            # - Если пришли по реф-ссылке: ещё +3 кредита (итого 6)
            # - Пригласившему: +3 кредита
            db_manager.add_credits(username, 3, 'welcome_bonus')
            
            if referrer_username:
                db_manager.add_credits(username, 3, f'referral_extra_bonus')
                db_manager.add_credits(referrer_username, 3, f'referral_bonus_for_{username}')
                audit('referral_registration', target=username, username_override=referrer_username, details={'invited_bonus': 6, 'referrer_bonus': 3})

            if invite_code:
                db_manager.use_invite(invite_code, username)
                try:
                    inv = db_manager.get_invite(invite_code)
                    if inv and inv['org_id']:
                        db_manager.add_org_member(inv['org_id'], username, 'scanner')
                        print(f"[REGISTER] {username} auto-joined org {inv['org_id']}", flush=True)
                except Exception as e:
                    print(f"[REGISTER] org auto-join failed: {e}", flush=True)
            verify_link = f"{DOMAIN_URL}/verify/{username}"
            audit('register', target=username, username_override=username, details={'email': email, 'plan': plan})
            email_body = (
                f"Здравствуйте, {username}!\n\n"
                f"Спасибо за регистрацию в AI-SecScan.\n\n"
                f"Для подтверждения аккаунта перейдите по ссылке:\n"
                f"{verify_link}\n\n"
                f"Если вы не регистрировались — просто проигнорируйте это письмо.\n\n"
                f"--\nКоманда AI-SecScan\nhttps://aisecscan.by"
            )
            try:
                send_email_async(email, "AI-SecScan: Подтвердите ваш email", email_body)
            except Exception as e:
                print(f"[REGISTER] send_email failed: {e}", flush=True)
            flash("Аккаунт успешно создан! Мы отправили ссылку для подтверждения на email. Проверьте почту (и папку Спам).")
            return redirect(url_for('login'))
        return render_template('register.html', error="Пользователь уже существует")
    return render_template('register.html')

@app.route('/verify/<username>', methods=['GET', 'POST'])
def verify(username):
    db_manager.verify_user_email(username)
    return render_template('login.html', error="Аккаунт успешно подтвержден! Теперь вы можете войти.")

@app.route('/resend_verification')
def resend_verification():
    username = request.args.get('username', '').strip()
    if not username:
        return redirect(url_for('login'))
    user = db_manager.get_user(username)
    if not user:
        return render_template('login.html', error="Пользователь с таким именем не найден.")
    if user['is_verified']:
        return render_template('login.html', error="Этот email уже подтверждён. Можете войти.")
    verify_link = f"{DOMAIN_URL}/verify/{username}"
    email_body = (
        f"Здравствуйте, {username}!\n\n"
        f"Вы запросили повторную отправку ссылки для подтверждения email в AI-SecScan.\n\n"
        f"Ссылка для подтверждения:\n{verify_link}\n\n"
        f"--\nКоманда AI-SecScan\nhttps://aisecscan.by"
    )
    try:
        send_email_async(user['email'], "AI-SecScan: Повторное подтверждение email", email_body)
    except Exception as e:
        print(f"[RESEND] failed: {e}", flush=True)
        return render_template('login.html', error=f"Не удалось отправить письмо: {e}")
    return render_template('login.html', error="Письмо отправлено повторно. Проверьте почту (и папку Спам).")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db_manager.get_user(username)

        if user and check_password_hash(user['password_hash'], password):

            if not user['is_verified']:
                audit('login_unverified', username_override=username)
                return render_template(
                    'login.html',
                    error=f"Email не подтверждён. Проверьте почту или <a href='/resend_verification?username={username}'>отправьте письмо повторно</a>."
                )

            if user['totp_secret']:
                audit('login_2fa_pending', username_override=username)
                session['pending_2fa_user'] = username
                return redirect(url_for('verify_2fa'))

            audit('login_success', username_override=username)
            session['username'] = username
            return redirect(url_for('profile'))

        audit('login_failed', username_override=username, details={'reason': 'bad_password'})
        return render_template('login.html', error="Неверный логин или пароль")
    return render_template('login.html')


@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pending_2fa_user' not in session: return redirect(url_for('login'))
    if request.method == 'POST':
        code = request.form['code']
        user = db_manager.get_user(session['pending_2fa_user'])
        totp = pyotp.TOTP(user['totp_secret'])
        if totp.verify(code):
            _u2fa = session.get('pending_2fa_user')
            audit('login_2fa_success', username_override=_u2fa)
            session['username'] = session.pop('pending_2fa_user')
            return redirect(url_for('profile'))
        return render_template('2fa.html', error="Неверный код. Попробуйте снова.")
    return render_template('2fa.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/api/setup_2fa', methods=['POST'])
def setup_2fa():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    user = db_manager.get_user(session['username'])
    if user['totp_secret']: return jsonify({"error": "2FA уже включена"}), 400
        
    secret = pyotp.random_base32()
    db_manager.update_2fa_secret(session['username'], secret)
    audit('2fa_enabled')
    
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=session['username'], issuer_name="AI-SecScan")
    img = qrcode.make(uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return jsonify({"status": "success", "qr_code": img_str, "secret": secret})

@app.route('/api/disable_2fa', methods=['POST'])
def api_disable_2fa():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    data = request.get_json()
    user = db_manager.get_user(session['username'])
    if not check_password_hash(user['password_hash'], data.get('password')):
        return jsonify({"error": "Неверный пароль"}), 403
    db_manager.disable_2fa(session['username'])
    audit('2fa_disabled')
    return jsonify({"status": "success"})

@app.route('/api/update_email', methods=['POST'])
def api_update_email():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    data = request.get_json()
    user = db_manager.get_user(session['username'])
    if not check_password_hash(user['password_hash'], data.get('password')):
        return jsonify({"error": "Неверный пароль"}), 403
    db_manager.update_user_email(session['username'], data.get('email'))
    audit('email_changed', details={'new_email': data.get('email')})
    return jsonify({"status": "success", "message": "Email обновлен. Подтвердите новый адрес в логах."})

@app.route('/api/update_password', methods=['POST'])
def api_update_password():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    data = request.get_json()
    user = db_manager.get_user(session['username'])
    if not check_password_hash(user['password_hash'], data.get('current_password')):
        return jsonify({"error": "Неверный текущий пароль"}), 403
    
    new_hash = generate_password_hash(data.get('new_password'))
    db_manager.update_user_password(session['username'], new_hash)
    audit('password_changed')
    return jsonify({"status": "success", "message": "Пароль успешно изменен!"})

@app.route('/api/beta_feedback', methods=['POST'])
def api_beta_feedback():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    data = request.get_json()
    msg = data.get('message', '').strip()
    if not msg: return jsonify({"error": "Текст отзыва не может быть пустым"}), 400
    db_manager.save_beta_feedback(session['username'], msg)
    return jsonify({"status": "success", "message": "Отзыв отправлен!"})

def process_scan(username, filename, code, use_ai, user_baselines, custom_rules):
    findings = scanner.scan_code(code, filename, user_baselines, custom_rules)
    if use_ai:
        ai_findings = ai_scanner.analyze_code(code)
        findings.extend(ai_findings)
    for f in findings:
        if "error" not in f: f["file"] = filename
    return findings

@app.route('/api/scan', methods=['POST'])
@limiter.limit("10 per minute")
def scan():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    username = session['username']
    allowed, scans_left = db_manager.check_and_increment_limit(username)
    if not allowed: return jsonify({"error": "Лимит сканирований исчерпан."}), 403

    allowed_exts = ['.py', '.js', '.php', '.java', '.ts', '.env', '.yml', '.yaml', '.json', '.txt', '.cfg', '.ini', '.xml']
    filename = "manual_input.py"
    user_baselines = db_manager.get_user_baselines(username)
    custom_rules = db_manager.get_custom_rules(username)
    findings = []
    
    use_ai = (request.is_json and request.json.get('use_ai')) or (request.form.get('use_ai') == 'true')

    if 'file' in request.files and request.files['file'].filename.endswith('.zip'):
        file = request.files['file']
        filename = file.filename
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, "project.zip")
        file.save(zip_path)
        
        try:
            extract_dir = os.path.join(temp_dir, "extracted")
            os.makedirs(extract_dir)
            safe_extract_zip(zip_path, extract_dir)
            
            ai_files_processed = 0
            for root, dirs, files in os.walk(extract_dir):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                for f in files:
                    filepath = os.path.join(root, f)
                    rel_path = os.path.relpath(filepath, extract_dir)
                    
                    if f in scan_core.DEPENDENCY_FILES:
                        sca_findings = scan_core.process_dependency_file(filepath, rel_path)
                        findings.extend(sca_findings)
                        if f == 'requirements.txt':
                            with open(filepath, 'r', encoding='utf-8-sig', errors='ignore') as req_file:
                                req_content = req_file.read()
                            sbom_data = SBOMGenerator.generate_cyclonedx(req_content, filename)
                            db_manager.save_sbom(username, filename, sbom_data)
                    elif any(f.endswith(ext) for ext in allowed_exts) or f.lower() == 'dockerfile':
                        with open(filepath, 'r', encoding='utf-8-sig', errors='ignore') as code_file:
                            code = code_file.read()
                        file_findings = scanner.scan_code(code, rel_path, user_baselines, custom_rules)
                        for finding in file_findings:
                            if "error" not in finding: finding["file"] = rel_path
                            findings.append(finding)
                        if use_ai and ai_files_processed < 2:
                            ai_findings = ai_scanner.analyze_code(code)
                            for a_f in ai_findings: a_f["file"] = rel_path
                            findings.extend(ai_findings)
                            ai_files_processed += 1
        finally: shutil.rmtree(temp_dir)

    elif 'file' in request.files:
        file = request.files['file']
        is_allowed = any(file.filename.endswith(ext) for ext in allowed_exts) or file.filename.lower() in ['env', 'config', 'credentials', '.env', '.gitignore', 'dockerfile', 'docker-compose.yml']
        if not is_allowed: return jsonify({"error": "Этот тип файлов не поддерживается."}), 400
        filename = file.filename
        code = file.read().decode('utf-8-sig')
        findings = process_scan(username, filename, code, use_ai, user_baselines, custom_rules)

    elif request.is_json and 'code' in request.json:
        code = request.json['code']
        filename = request.json.get('filename', 'manual_input.py')
        findings = process_scan(username, filename, code, use_ai, user_baselines, custom_rules)
    else: return jsonify({"error": "Не передан код или файл"}), 400

    unique_findings = []
    seen = set()
    for f in findings:
        if "error" in f:
            unique_findings.append(f)
            continue
        key = f"{f.get('file')}_{f.get('rule_id')}_{f.get('line')}"
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    
    findings = unique_findings
    score, grade = calculate_score(findings)
    
    if not (len(findings) == 1 and "error" in findings[0]): 
        db_manager.save_scan_report(username, filename, findings)
    
    return jsonify({"status": "success", "filename": filename, "findings": findings, "scans_left": scans_left, "score": score, "grade": grade})

@app.route('/api/scan_async', methods=['POST'])
@limiter.limit("10 per minute")
def scan_async():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    username = session['username']
    allowed, scans_left = db_manager.check_and_increment_limit(username)
    if not allowed: return jsonify({"error": "Лимит сканирований исчерпан."}), 403

    use_ai = (request.is_json and request.json.get('use_ai')) or (request.form.get('use_ai') == 'true')

    import io, base64 as _b64, zipfile as _zip

    if 'file' in request.files:
        file = request.files['file']
        filename = file.filename
        data = file.read()
        if not filename.lower().endswith('.zip'):
            buf = io.BytesIO()
            with _zip.ZipFile(buf, 'w', _zip.ZIP_DEFLATED) as z:
                z.writestr(filename, data)
            data = buf.getvalue()
    elif request.is_json and 'code' in request.json:
        code = request.json['code']
        filename = request.json.get('filename', 'manual_input.py')
        buf = io.BytesIO()
        with _zip.ZipFile(buf, 'w', _zip.ZIP_DEFLATED) as z:
            z.writestr(filename, code)
        data = buf.getvalue()
    else:
        return jsonify({"error": "Не передан код или файл"}), 400

    from tasks import scan_project_task
    b64 = _b64.b64encode(data).decode()
    task = scan_project_task.delay(username, b64, filename, use_ai)

    return jsonify({
        "status": "queued",
        "task_id": task.id,
        "filename": filename,
        "scans_left": scans_left,
    }), 202


@app.route('/api/scan_async/status/<task_id>', methods=['GET'])
def scan_async_status(task_id):
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401

    from celery.result import AsyncResult
    from celery_app import celery_app as _ca
    r = AsyncResult(task_id, app=_ca)

    response = {"task_id": task_id, "state": r.state}
    if r.state == 'PROGRESS' and r.info:
        response['progress'] = r.info
    elif r.state == 'SUCCESS':
        response['result'] = r.result
    elif r.state == 'FAILURE':
        response['error'] = str(r.info)
    return jsonify(response)


@app.route('/api/scan_github', methods=['POST'])
@limiter.limit("5 per minute")
def scan_github():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    username = session['username']
    allowed, scans_left = db_manager.check_and_increment_limit(username)
    if not allowed: return jsonify({"error": "Лимит сканирований исчерпан."}), 403

    data = request.get_json()
    repo_url = data.get('repo_url', '').strip()
    use_ai = data.get('use_ai', False)

    if not repo_url or 'github.com' not in repo_url:
        return jsonify({"error": "Укажите корректную ссылку на GitHub"}), 400

    repo_url = repo_url.rstrip('/').replace('.git', '')
    parts = repo_url.split('github.com/')
    if len(parts) < 2: return jsonify({"error": "Неверный формат URL"}), 400
    
    repo_path = parts[1]
    if repo_path.count('/') != 1: return jsonify({"error": "Укажите ссылку на корень репозитория"}), 400

    filename = f"{repo_path.replace('/', '_')}.zip"
    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, "repo.zip")
    extract_dir = os.path.join(temp_dir, "extracted")

    try:
        zip_url = f"https://github.com/{repo_path}/archive/refs/heads/main.zip"
        resp = requests.get(zip_url, stream=True, timeout=30)
        if resp.status_code != 200:
            zip_url = f"https://github.com/{repo_path}/archive/refs/heads/master.zip"
            resp = requests.get(zip_url, stream=True, timeout=30)
            
        if resp.status_code != 200:
            return jsonify({"error": "Не удалось скачать репозиторий. Возможно, он приватный или не существует."}), 400

        with open(zip_path, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)

        os.makedirs(extract_dir)
        safe_extract_zip(zip_path, extract_dir)

        findings = []
        user_baselines = db_manager.get_user_baselines(username)
        custom_rules = db_manager.get_custom_rules(username)
        allowed_exts = ['.py', '.js', '.php', '.java', '.ts', '.env', '.yml', '.yaml', '.json', '.txt', '.cfg', '.ini', '.xml']
        
        ai_files_processed = 0
        top_folder = os.listdir(extract_dir)[0]
        
        for root, dirs, files in os.walk(extract_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for f in files:
                filepath = os.path.join(root, f)
                rel_path = os.path.relpath(filepath, extract_dir)
                if rel_path.startswith(top_folder):
                    rel_path = rel_path[len(top_folder):].lstrip('/\\')

                if f in scan_core.DEPENDENCY_FILES:
                    sca_findings = scan_core.process_dependency_file(filepath, rel_path)
                    findings.extend(sca_findings)
                    if f == 'requirements.txt':
                        with open(filepath, 'r', encoding='utf-8-sig', errors='ignore') as req_file:
                            req_content = req_file.read()
                        sbom_data = SBOMGenerator.generate_cyclonedx(req_content, filename)
                        db_manager.save_sbom(username, filename, sbom_data)
                elif any(f.endswith(ext) for ext in allowed_exts) or f.lower() == 'dockerfile':
                    with open(filepath, 'r', encoding='utf-8-sig', errors='ignore') as code_file:
                        code = code_file.read()
                    file_findings = scanner.scan_code(code, rel_path, user_baselines, custom_rules)
                    for finding in file_findings:
                        if "error" not in finding: finding["file"] = rel_path
                        findings.append(finding)
                    if use_ai and ai_files_processed < 2:
                        ai_findings = ai_scanner.analyze_code(code)
                        for a_f in ai_findings: a_f["file"] = rel_path
                        findings.extend(ai_findings)
                        ai_files_processed += 1

        unique_findings = []
        seen = set()
        for f in findings:
            if "error" in f:
                unique_findings.append(f)
                continue
            key = f"{f.get('file')}_{f.get('rule_id')}_{f.get('line')}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        
        findings = unique_findings
        score, grade = calculate_score(findings)
        
        if not (len(findings) == 1 and "error" in findings[0]): 
            db_manager.save_scan_report(username, filename, findings)
        
        return jsonify({"status": "success", "filename": filename, "findings": findings, "scans_left": scans_left, "score": score, "grade": grade})

    except Exception as e:
        return jsonify({"error": f"Ошибка при скачивании: {str(e)}"}), 500
    finally:
        shutil.rmtree(temp_dir)

@app.route('/api/last_scan', methods=['GET'])
def last_scan():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    filename, findings = db_manager.get_last_scan_report(session['username'])
    if not filename: return jsonify({"status": "empty"})
    score, grade = calculate_score(findings)
    return jsonify({"status": "success", "filename": filename, "findings": findings, "score": score, "grade": grade})

@app.route('/api/fix', methods=['POST'])
@limiter.limit("5 per minute")
def ai_fix():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    data = request.get_json()
    code = data.get('code')
    issue = data.get('issue')
    if not code or not issue: return jsonify({"error": "Нет данных"}), 400
    
    def generate():
        for chunk in ai_scanner.stream_fix(code, issue, data.get('file', 'unknown.py')):
            yield chunk
            
    return Response(stream_with_context(generate()), mimetype='text/plain', headers={'X-Accel-Buffering': 'no', 'Cache-Control': 'no-cache'})

@app.route('/api/feedback', methods=['POST'])
@limiter.limit("30 per minute")
def feedback():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    data = request.get_json()
    finding_hash = data.get('finding_hash')
    if finding_hash:
        status = "TruePositive" if data.get('is_tp') else "FalsePositive"
        db_manager.save_user_baseline(session['username'], finding_hash, status)
    return jsonify({"status": "success", "new_weight": 0.0 if not data.get('is_tp') else 1.0})

@app.route('/api/generate_key', methods=['POST'])
def generate_key():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    data = request.get_json() or {}
    key_name = data.get('name', 'My API Key')
    new_key, error = db_manager.create_api_key(session['username'], key_name)
    if error: return jsonify({"error": error}), 403
    audit('api_key_created', target=key_name, details={'key_prefix': new_key[:12] if new_key else None})
    return jsonify({"status": "success", "api_key": new_key})

@app.route('/api/delete_key/<int:key_id>', methods=['DELETE'])
def delete_key(key_id):
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    db_manager.delete_api_key(key_id, session['username'])
    audit('api_key_deleted', target=str(key_id))
    return jsonify({"status": "success"})

@app.route('/api/webhook', methods=['POST'])
def save_webhook():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    data = request.get_json()
    url = data.get('url', '')
    db_manager.set_webhook(session['username'], url)
    return jsonify({"status": "success"})

@app.route('/api/create_task', methods=['POST'])
def create_task():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    username = session['username']
    user = db_manager.get_user(username)
    
    webhook_url = user['webhook_url'] if user else None
    if not webhook_url:
        return jsonify({"error": "Webhook URL не настроен."}), 400
        
    data = request.get_json()
    payload = {
        "title": f"[AI-SecScan] {data.get('rule_id')} в {data.get('file')}",
        "description": f"Уровень: {data.get('severity')}\nСтрока: {data.get('line')}\nКод: {data.get('code')}\nОписание: {data.get('message')}",
        "project": "AI-SecScan"
    }
    
    try:
        resp = requests.post(webhook_url, json=payload, timeout=5)
        if resp.status_code in [200, 201, 204]:
            return jsonify({"status": "success", "message": "Задача успешно отправлена!"})
        else:
            return jsonify({"error": f"Трекер вернул код {resp.status_code}"}), 400
    except Exception as e:
        return jsonify({"error": f"Ошибка сети: {str(e)}"}), 500

@app.route('/api/rules', methods=['POST'])
def add_rule():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    data = request.get_json()
    rule_id = data.get('rule_id', 'CUSTOM_RULE')
    severity = data.get('severity', 'HIGH')
    pattern = data.get('pattern')
    message = data.get('message', 'Сработало правило.')
    
    if not pattern: return jsonify({"error": "Regex не может быть пустым"}), 400
    try: re.compile(pattern)
    except re.error: return jsonify({"error": "Неверный синтаксис Regex"}), 400
        
    db_manager.add_custom_rule(session['username'], rule_id, severity, pattern, message)
    return jsonify({"status": "success"})

@app.route('/api/rules/<int:rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    db_manager.delete_custom_rule(rule_id, session['username'])
    return jsonify({"status": "success"})

@app.route('/api/v1/scan', methods=['POST'])
def api_v1_scan():
    """
    Сканирование кода через API
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
        description: "Bearer <API_KEY>"
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            code:
              type: string
              description: "Исходный код для проверки"
            filename:
              type: string
              description: "Имя файла (например, test.py или Dockerfile)"
    responses:
      200:
        description: Успешный скан
      401:
        description: Неверный API-ключ
    """
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"error": "Отсутствует заголовок Authorization"}), 401
        
    parts = auth_header.split(" ")
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return jsonify({"error": "Неверный формат токена. Используйте 'Bearer <API_KEY>'"}), 401
        
    api_key = parts[1]
    user = db_manager.get_user_by_api_key(api_key)
    if not user: return jsonify({"error": "Неверный API-ключ"}), 401
    if user['plan'] == 'free': return jsonify({"error": "API доступно только на Pro"}), 403
        
    username = user['username']
    allowed, scans_left = db_manager.check_and_increment_limit(username)
    if not allowed: return jsonify({"error": "Лимит сканирований исчерпан."}), 403

    data = request.get_json()
    if not data or 'code' not in data: return jsonify({"error": "Не передан код"}), 400
        
    code = data['code']
    filename = data.get('filename', 'api_upload.py')
    
    user_baselines = db_manager.get_user_baselines(username)
    custom_rules = db_manager.get_custom_rules(username)
    
    findings = process_scan(username, filename, code, False, user_baselines, custom_rules)
    
    if not (len(findings) == 1 and "error" in findings[0]):
        db_manager.save_scan_report(username, filename, findings)
        
    score, grade = calculate_score(findings)
    return jsonify({"status": "success", "filename": filename, "findings": findings, "score": score, "grade": grade})

@app.route('/api/change_plan', methods=['POST'])
def api_change_plan():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    data = request.get_json()
    new_plan = data.get('plan')
    if new_plan not in ['free', 'pro', 'startup', 'team', 'enterprise']:
        return jsonify({"error": "Неверный тариф"}), 400
    db_manager.change_user_plan(session['username'], new_plan)
    return jsonify({"status": "success", "message": "Тариф успешно изменен!"})

@app.route('/api/report/sbom')
def api_report_sbom():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    username = session['username']
    sbom_filename, sbom_json = db_manager.get_last_sbom(username)
    if not sbom_json:
        return jsonify({"error": "SBOM не найден. Загрузите ZIP с requirements.txt (или package.json/go.mod/pom.xml)."}), 404
    return Response(
        sbom_json,
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment;filename={sbom_filename or "sbom.json"}.cdx.json'}
    )


@app.route('/api/report/<format>', methods=['GET'])
def download_report(format):
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    filename, findings = db_manager.get_last_scan_report(session['username'])
    if not filename: return "Сначала выполните сканирование", 400
    score, grade = calculate_score(findings)
        
    if format == 'sbom':
        sbom_filename, sbom_json = db_manager.get_last_sbom(session['username'])
        if not sbom_json: return "SBOM не найден. Загрузите файл requirements.txt для генерации.", 404
        return Response(sbom_json, mimetype='application/json', headers={'Content-Disposition': f'attachment;filename=sbom.json'})
    elif format == 'json':
        return Response(ReportGenerator.generate_json(findings, filename, score, grade), mimetype='application/json', headers={'Content-Disposition': f'attachment;filename=report.json'})
    elif format == 'sarif':
        return Response(ReportGenerator.generate_sarif(findings, filename, score, grade), mimetype='application/json', headers={'Content-Disposition': f'attachment;filename=report.sarif'})
    elif format == 'pdf':
        return Response(ReportGenerator.generate_pdf(findings, filename, score, grade), mimetype='application/pdf', headers={'Content-Disposition': f'attachment;filename=report.pdf'})
    return "Неверный формат", 400

# ============ ADMIN ROUTES ============

from analytics import parse_nginx_log

@app.route('/api/admin/analytics')
def api_admin_analytics():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    if not db_manager.is_admin(session['username']): return jsonify({"error": "Доступ запрещен"}), 403
    return jsonify(parse_nginx_log())

@app.route('/admin')
def admin_panel():
    if 'username' not in session: return redirect(url_for('login'))
    user = db_manager.get_user(session['username'])
    if not user or not user['is_admin']:
        return "Доступ запрещен. Только для администраторов.", 403
    return render_template('admin.html', user=user)

@app.route('/api/admin/users')
def api_admin_users():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    if not db_manager.is_admin(session['username']): return jsonify({"error": "Доступ запрещен"}), 403
    users = db_manager.get_all_users()
    return jsonify([dict(u) for u in users])

@app.route('/api/admin/user/<username>/update', methods=['POST'])
def api_admin_user_update(username):
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    if not db_manager.is_admin(session['username']): return jsonify({"error": "Доступ запрещен"}), 403
    data = request.get_json()
    if db_manager.admin_update_user(username, data.get('field'), data.get('value')):
        audit('admin_update_user', target=username, details={'field': data.get('field'), 'value': data.get('value')})
        return jsonify({"status": "success"})
    return jsonify({"error": "Ошибка обновления"}), 400

@app.route('/api/admin/user/<username>/delete', methods=['POST'])
def api_admin_user_delete(username):
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    if not db_manager.is_admin(session['username']): return jsonify({"error": "Доступ запрещен"}), 403
    if username == session['username']:
        return jsonify({"error": "Нельзя удалить самого себя"}), 400
    db_manager.admin_delete_user(username)
    audit('admin_delete_user', target=username)
    return jsonify({"status": "success"})

@app.route('/api/admin/user/<username>/reset_password', methods=['POST'])
def api_admin_user_reset_pwd(username):
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    if not db_manager.is_admin(session['username']): return jsonify({"error": "Доступ запрещен"}), 403
    data = request.get_json()
    new_pwd = data.get('new_password', '')
    if len(new_pwd) < 6: return jsonify({"error": "Пароль должен быть от 6 символов"}), 400
    db_manager.admin_reset_password(username, generate_password_hash(new_pwd))
    audit('admin_reset_password', target=username)
    return jsonify({"status": "success"})

@app.route('/api/admin/invites')
def api_admin_invites():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    if not db_manager.is_admin(session['username']): return jsonify({"error": "Доступ запрещен"}), 403
    invites = db_manager.get_all_invites()
    return jsonify([dict(i) for i in invites])

@app.route('/api/admin/invite/create', methods=['POST'])
def api_admin_invite_create():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    if not db_manager.is_admin(session['username']): return jsonify({"error": "Доступ запрещен"}), 403
    data = request.get_json()
    code = db_manager.create_invite(
        session['username'],
        data.get('plan', 'pro'),
        int(data.get('max_uses', 1)),
        int(data.get('days', 7))
    )
    audit('admin_invite_create', target=code, details={'plan': data.get('plan', 'pro'), 'max_uses': data.get('max_uses', 1)})
    return jsonify({"status": "success", "code": code})

@app.route('/api/admin/invite/<int:invite_id>/delete', methods=['POST'])
def api_admin_invite_delete(invite_id):
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    if not db_manager.is_admin(session['username']): return jsonify({"error": "Доступ запрещен"}), 403
    db_manager.delete_invite(invite_id)
    audit('admin_invite_delete', target=str(invite_id))
    return jsonify({"status": "success"})

@app.route('/admin/audit')
def admin_audit():
    if 'username' not in session: return redirect(url_for('login'))
    user = db_manager.get_user(session['username'])
    if not user or not user['is_admin']:
        return "Доступ запрещен. Только для администраторов.", 403
    return render_template('audit.html', user=user)


@app.route('/api/admin/audit')
def api_admin_audit():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    if not db_manager.is_admin(session['username']): return jsonify({"error": "Доступ запрещен"}), 403
    username = request.args.get('user', '').strip() or None
    action = request.args.get('action', '').strip() or None
    try:
        limit = min(int(request.args.get('limit', 100)), 500)
        offset = max(int(request.args.get('offset', 0)), 0)
    except ValueError:
        limit, offset = 100, 0
    rows = db_manager.get_audit_log(username=username, action=action, limit=limit, offset=offset)
    total = db_manager.get_audit_count(username=username, action=action)
    return jsonify({
        "total": total,
        "limit": limit,
        "offset": offset,
        "rows": [dict(r) for r in rows],
    })


@app.route('/api/admin/audit/actions')
def api_admin_audit_actions():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    if not db_manager.is_admin(session['username']): return jsonify({"error": "Доступ запрещен"}), 403
    return jsonify(db_manager.get_audit_actions())


# ============ ORGANIZATIONS API ============

@app.route('/org')
def org_page():
    if 'username' not in session: return redirect(url_for('login'))
    user = db_manager.get_user(session['username'])
    if not user: return redirect(url_for('login'))
    return render_template('org.html', user=user)


@app.route('/api/scan_diff', methods=['POST'])
@limiter.limit("20 per minute")
def api_scan_diff():
    # Авторизация: либо Bearer, либо сессия
    api_key = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
    user = None
    if api_key:
        user = db_manager.get_user_by_api_key(api_key)
    if not user and 'username' in session:
        user = db_manager.get_user(session['username'])
    if not user:
        return jsonify({"error": "Не авторизован (нужен Bearer API-ключ или сессия)"}), 401

    username = user['username']
    data = request.get_json() or {}
    diff_text = data.get('diff', '')
    if not diff_text.strip():
        return jsonify({"error": "Пустой diff"}), 400

    from scanner.diff_parser import parse_unified_diff
    added_lines = parse_unified_diff(diff_text)
    if not added_lines:
        return jsonify({"status": "success", "findings": [], "summary": {"total_issues": 0}, "message": "Нет добавленных строк"})

    user_baselines = db_manager.get_user_baselines(username)
    custom_rules = db_manager.get_custom_rules(username)
    findings = []

    for item in added_lines:
        try:
            file_findings = scanner.scan_code(item['code'], item['file'], user_baselines, custom_rules)
            for f in file_findings:
                if "error" not in f:
                    f['file'] = item['file']
                    f['line'] = item['line']
                findings.append(f)
        except Exception:
            pass

    score, grade = calculate_score(findings)
    audit('scan_diff', details={'files': len(set(x['file'] for x in added_lines)), 'added_lines': len(added_lines), 'findings': len(findings)}, username_override=username)

    return jsonify({
        "status": "success",
        "summary": {
            "total_issues": len(findings),
            "added_lines_scanned": len(added_lines),
            "files": len(set(x['file'] for x in added_lines))
        },
        "score": score,
        "grade": grade,
        "findings": findings
    })


@app.route('/api/get_full_key/<int:key_id>')
def api_get_full_key(key_id):
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    keys = db_manager.get_user_api_keys(session['username'])
    for k in keys:
        if k['id'] == key_id:
            return jsonify({"api_key": k['api_key']})
    return jsonify({"error": "Ключ не найден"}), 404


@app.route('/api/clear_history', methods=['POST'])
def api_clear_history():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    username = session['username']
    try:
        conn = db_manager.get_db()
        conn.execute("DELETE FROM scans WHERE username = ?", (username,))
        conn.execute("DELETE FROM scan_reports WHERE username = ?", (username,))
        conn.execute("DELETE FROM sboms WHERE username = ?", (username,))
        conn.commit()
        conn.close()
        audit('history_cleared', details={'deleted': True})
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/referral/stats')
def api_referral_stats():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    return jsonify(db_manager.get_referral_stats(session['username']))


@app.route('/api/buy_credits', methods=['POST'])
def api_buy_credits():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    username = session['username']
    data = request.get_json() or {}
    package = data.get('package')

    packages = {
        'start': {'amount': 10, 'price': 5},
        'business': {'amount': 50, 'price': 20},
        'pro': {'amount': 200, 'price': 60}
    }

    if package not in packages:
        return jsonify({"error": "Неверный пакет"}), 400

    # MVP: имитация успешной оплаты (потом заменим на вебхук Оплати/WebPay)
    amount = packages[package]['amount']
    price = packages[package]['price']
    
    if db_manager.add_credits(username, amount, f'mock_purchase_{package}'):
        # Бонус рефереру (10% от купленного пакета, минимум 1)
        user = db_manager.get_user(username)
        if user and user['referred_by']:
            ref_bonus = max(1, amount // 10)
            db_manager.add_credits(user['referred_by'], ref_bonus, f'referral_purchase_bonus_from_{username}')
            audit('referral_purchase_bonus', target=user['referred_by'], details={'from_user': username, 'bonus': ref_bonus})
        
        audit('credits_purchased', details={'package': package, 'amount': amount, 'price': price})
        return jsonify({"status": "success", "amount": amount, "message": f"Начислено {amount} сканов (тестовый режим)"})
    else:
        return jsonify({"error": "Ошибка начисления"}), 500


@app.route('/api/cookie_consent', methods=['POST'])
def api_cookie_consent():
    data = request.get_json() or {}
    # Логируем в аудит, если пользователь авторизован
    if 'username' in session:
        audit('cookie_consent', details={'analytics': data.get('analytics'), 'marketing': data.get('marketing')})
    else:
        # Для анонимных пользователей пишем в лог
        print(f"[COOKIE] Anonymous consent: analytics={data.get('analytics')}, marketing={data.get('marketing')}", flush=True)
    return jsonify({"status": "success"}), 200


@app.route('/api/stats/trend')
def api_stats_trend():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    return jsonify(db_manager.get_user_trend(session['username']))


@app.route('/api/org/create', methods=['POST'])
def api_org_create():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    user = db_manager.get_user(session['username'])
    if user['plan'] not in ('startup', 'team', 'enterprise'):
        return jsonify({"error": "Организации доступны на тарифах Startup, Team и Enterprise"}), 403

    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name or len(name) < 2:
        return jsonify({"error": "Имя организации минимум 2 символа"}), 400

    org_id = db_manager.create_organization(name, session['username'], plan='team')
    if not org_id:
        return jsonify({"error": "Не удалось создать организацию"}), 500

    audit('org_created', target=str(org_id), details={'name': name})
    return jsonify({"status": "success", "org_id": org_id, "name": name})


@app.route('/api/org/list', methods=['GET'])
def api_org_list():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    orgs = db_manager.get_user_orgs(session['username'])
    return jsonify([dict(o) for o in orgs])


@app.route('/api/org/<int:org_id>/invite', methods=['POST'])
def api_org_invite(org_id):
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    if not db_manager.is_org_admin(org_id, session['username']):
        return jsonify({"error": "Только owner/admin могут приглашать"}), 403

    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    if not email or '@' not in email:
        return jsonify({"error": "Укажите корректный email"}), 400

    org = db_manager.get_organization(org_id)
    if not org:
        return jsonify({"error": "Организация не найдена"}), 404

    # Создаём инвайт с привязкой к org
    code = db_manager.create_invite(
        created_by=session['username'],
        plan=org['plan'],
        max_uses=1,
        days=7,
        org_id=org_id,
        email=email
    )

    verify_link = f"{DOMAIN_URL}/register?invite={code}"
    body = (
        f"Здравствуйте!\n\n"
        f"{session['username']} приглашает вас в организацию \"{org['name']}\" на платформе AI-SecScan.\n\n"
        f"Зарегистрируйтесь по ссылке (или введите код вручную):\n"
        f"{verify_link}\n\n"
        f"Код приглашения: {code}\n\n"
        f"Ссылка действует 7 дней.\n\n"
        f"--\nКоманда AI-SecScan\nhttps://aisecscan.by"
    )

    try:
        send_email_async(email, f"Приглашение в {org['name']} (AI-SecScan)", body)
        email_status = "sent"
    except Exception as e:
        print(f"[INVITE] email failed: {e}", flush=True)
        email_status = "failed"

    audit('org_invite_sent', target=email, details={'org_id': org_id, 'code': code})
    return jsonify({"status": "success", "code": code, "email_status": email_status})


@app.route('/api/org/<int:org_id>/members', methods=['GET'])
def api_org_members(org_id):
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    if not db_manager.get_user_role_in_org(org_id, session['username']):
        return jsonify({"error": "Нет доступа к организации"}), 403
    members = db_manager.get_org_members(org_id)
    return jsonify([dict(m) for m in members])


# ============ ORGANIZATIONS: MEMBER MANAGEMENT ============

@app.route('/api/org/<int:org_id>/add_member', methods=['POST'])
def api_org_add_member(org_id):
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    if not db_manager.is_org_admin(org_id, session['username']):
        return jsonify({"error": "Только owner/admin могут добавлять участников"}), 403

    data = request.get_json() or {}
    target = (data.get('username') or '').strip()
    role = data.get('role', 'scanner')
    if role not in ('admin', 'scanner', 'viewer'):
        return jsonify({"error": "Неверная роль"}), 400
    if not target:
        return jsonify({"error": "Укажите username"}), 400

    user = db_manager.get_user(target)
    if not user:
        return jsonify({"error": f"Пользователь '{target}' не найден"}), 404

    db_manager.add_org_member(org_id, target, role)
    audit('org_member_added', target=target, details={'org_id': org_id, 'role': role})
    return jsonify({"status": "success"})


@app.route('/api/org/<int:org_id>/remove_member', methods=['POST'])
def api_org_remove_member(org_id):
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    if not db_manager.is_org_admin(org_id, session['username']):
        return jsonify({"error": "Только owner/admin могут удалять участников"}), 403

    data = request.get_json() or {}
    target = (data.get('username') or '').strip()
    if not target:
        return jsonify({"error": "Укажите username"}), 400
    if target == session['username']:
        return jsonify({"error": "Нельзя удалить себя"}), 400
    if db_manager.get_user_role_in_org(org_id, target) == 'owner':
        return jsonify({"error": "Нельзя удалить владельца организации"}), 400

    db_manager.remove_org_member(org_id, target)
    audit('org_member_removed', target=target, details={'org_id': org_id})
    return jsonify({"status": "success"})


@app.route('/api/org/<int:org_id>/change_role', methods=['POST'])
def api_org_change_role(org_id):
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    if db_manager.get_user_role_in_org(org_id, session['username']) != 'owner':
        return jsonify({"error": "Только owner может менять роли"}), 403

    data = request.get_json() or {}
    target = (data.get('username') or '').strip()
    new_role = data.get('role', '')
    if new_role not in ('admin', 'scanner', 'viewer'):
        return jsonify({"error": "Неверная роль"}), 400
    if not target or target == session['username']:
        return jsonify({"error": "Нельзя менять свою роль"}), 400

    db_manager.add_org_member(org_id, target, new_role)
    audit('org_role_changed', target=target, details={'org_id': org_id, 'role': new_role})
    return jsonify({"status": "success"})


@app.route('/robots.txt')
def robots_txt():
    from flask import Response
    txt = """User-agent: *
Disallow: /admin
Disallow: /api/
Disallow: /profile
Allow: /

Sitemap: https://aisecscan.by/sitemap.xml
"""
    return Response(txt, mimetype='text/plain')

@app.route('/sitemap.xml')
def sitemap_xml():
    from flask import Response
    from datetime import datetime
    today = datetime.now().strftime("%Y-%m-%d")
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url><loc>https://aisecscan.by/</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>1.0</priority></url>
    <url><loc>https://aisecscan.by/register</loc><lastmod>{today}</lastmod><changefreq>monthly</changefreq><priority>0.8</priority></url>
    <url><loc>https://aisecscan.by/login</loc><lastmod>{today}</lastmod><changefreq>monthly</changefreq><priority>0.5</priority></url>
    <url><loc>https://aisecscan.by/terms</loc><lastmod>{today}</lastmod><changefreq>yearly</changefreq><priority>0.3</priority></url>
</urlset>"""
    return Response(xml, mimetype='application/xml')


@app.route('/google355c3ebc960d5104.html')
def google_verify():
    from flask import Response
    return Response("google-site-verification: google355c3ebc960d5104.html", mimetype='text/html')


@app.route('/yandex_47481968951e9b26.html')
def yandex_verify():
    from flask import Response
    html = """<html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"></head><body>Verification: 47481968951e9b26</body></html>"""
    return Response(html, mimetype='text/html')



@app.route('/api/generate_github_action')
def generate_github_action():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401

    yaml_template = """name: AI-SecScan (Diff)
on:
  push:
    branches: [ "main", "master" ]
  pull_request:
    branches: [ "main", "master" ]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Get Diff
        run: |
          if [ "${{ github.event_name }}" == "pull_request" ]; then
            git fetch origin ${{ github.base_ref }}
            git diff origin/${{ github.base_ref }}...HEAD > diff.txt
          else
            git diff HEAD^ HEAD > diff.txt
          fi
          jq -Rs '{diff: .}' diff.txt > payload.json

      - name: Run AI-SecScan
        env:
          API_KEY: ${{ secrets.AISECSCAN_API_KEY }}
        run: |
          RESPONSE=$(curl -s -X POST https://aisecscan.by/api/scan_diff \\
            -H "Authorization: Bearer $API_KEY" \\
            -H "Content-Type: application/json" \\
            -d @payload.json)
          echo "AI-SecScan: found $CRITICAL critical/high issues. See details below."
          CRITICAL=$(echo "$RESPONSE" | jq '[.findings[] | select(.severity=="CRITICAL" or .severity=="HIGH")] | length')
          if [ "$CRITICAL" -gt 0 ]; then
            echo "::error::Найдено критических/высоких уязвимостей: $CRITICAL."
            exit 1
          fi
          echo "Проверка пройдена!"
"""
    return jsonify({"yaml": yaml_template})

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)