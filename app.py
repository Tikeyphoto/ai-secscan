import os
import re
import zipfile
import tempfile
import shutil
import requests
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, Response, stream_with_context
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from scanner.engine import SecurityScanner
from scanner.sca_engine import SCAEngine
from scanner.ai_engine import AIEngine
from report_generator import ReportGenerator
import db_manager

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_dev' 
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"], storage_uri="memory://")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(BASE_DIR, "scanner", "rules.json")
CVE_FILE = os.path.join(BASE_DIR, "scanner", "cve_db.json")

db_manager.init_db()
scanner = SecurityScanner(RULES_FILE)
sca_scanner = SCAEngine(CVE_FILE)
ai_scanner = AIEngine()

# Черный список директорий и файлов, которые не нужно сканировать
IGNORE_DIRS = ['venv', '.venv', 'env', 'site-packages', '__pycache__', 'node_modules', '.git', 'dist', 'build', 'migrations']
IGNORE_FILES = ['rules.json', 'cve_db.json', 'package-lock.json', 'yarn.lock']

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
    if 'username' not in session: 
        return render_template('landing.html')
    return redirect(url_for('profile'))

@app.route('/profile')
def profile():
    if 'username' not in session: return redirect(url_for('login'))
    user = db_manager.get_user(session['username'])
    if not user: session.clear(); return redirect(url_for('login'))
    history = db_manager.get_user_scans(session['username'])
    stats = db_manager.get_user_stats(session['username'])
    custom_rules = db_manager.get_custom_rules(session['username'])
    user_api_keys = db_manager.get_user_api_keys(session['username'])
    return render_template('profile.html', user=user, history=history, stats=stats, custom_rules=custom_rules, user_api_keys=user_api_keys)

@app.route('/upgrade', methods=['POST'])
def upgrade():
    if 'username' in session:
        db_manager.upgrade_user_plan(session['username'])
        flash('Поздравляем! Вы перешли на тариф Pro.')
    return redirect(url_for('profile'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if db_manager.create_user(username, generate_password_hash(password)): return redirect(url_for('login'))
        return render_template('register.html', error="Пользователь уже существует")
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db_manager.get_user(username)
        if user and check_password_hash(user['password_hash'], password):
            session['username'] = username
            return redirect(url_for('profile'))
        return render_template('login.html', error="Неверный логин или пароль")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

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
                # Игнорируем ненужные папки
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.')]
                
                for f in files:
                    if f in IGNORE_FILES: continue # Игнорируем служебные файлы
                    
                    filepath = os.path.join(root, f)
                    rel_path = os.path.relpath(filepath, extract_dir)
                    
                    if f == 'requirements.txt':
                        with open(filepath, 'r', encoding='utf-8-sig', errors='ignore') as req_file:
                            sca_findings = sca_scanner.scan_requirements(req_file.read())
                            for sca_f in sca_findings: sca_f["file"] = rel_path
                            findings.extend(sca_findings)
                    elif any(f.endswith(ext) for ext in allowed_exts):
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
        is_allowed = any(file.filename.endswith(ext) for ext in allowed_exts) or file.filename.lower() in ['env', 'config', 'credentials', '.env', '.gitignore']
        if not is_allowed: return jsonify({"error": "Этот тип файлов не поддерживается."}), 400
        filename = file.filename
        code = file.read().decode('utf-8-sig')
        findings = process_scan(username, filename, code, use_ai, user_baselines, custom_rules)

    elif request.is_json and 'code' in request.json:
        code = request.json['code']
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
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.')]
            
            for f in files:
                if f in IGNORE_FILES: continue
                
                filepath = os.path.join(root, f)
                rel_path = os.path.relpath(filepath, extract_dir)
                
                if rel_path.startswith(top_folder):
                    rel_path = rel_path[len(top_folder):].lstrip('/\\')

                if f == 'requirements.txt':
                    with open(filepath, 'r', encoding='utf-8-sig', errors='ignore') as req_file:
                        sca_findings = sca_scanner.scan_requirements(req_file.read())
                        for sca_f in sca_findings: sca_f["file"] = rel_path
                        findings.extend(sca_findings)
                elif any(f.endswith(ext) for ext in allowed_exts):
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
    return jsonify({"status": "success", "api_key": new_key})

@app.route('/api/delete_key/<int:key_id>', methods=['DELETE'])
def delete_key(key_id):
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    db_manager.delete_api_key(key_id, session['username'])
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
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Отсутствует заголовок Authorization"}), 401
    
    api_key = auth_header.split(" ")[1]
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

@app.route('/api/report/<format>', methods=['GET'])
def download_report(format):
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    filename, findings = db_manager.get_last_scan_report(session['username'])
    if not filename: return "Сначала выполните сканирование", 400
    score, grade = calculate_score(findings)
        
    if format == 'json':
        return Response(ReportGenerator.generate_json(findings, filename, score, grade), mimetype='application/json', headers={'Content-Disposition': f'attachment;filename=report.json'})
    elif format == 'sarif':
        return Response(ReportGenerator.generate_sarif(findings, filename, score, grade), mimetype='application/json', headers={'Content-Disposition': f'attachment;filename=report.sarif'})
    elif format == 'pdf':
        return Response(ReportGenerator.generate_pdf(findings, filename, score, grade), mimetype='application/pdf', headers={'Content-Disposition': f'attachment;filename=report.pdf'})
    return "Неверный формат", 400

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)