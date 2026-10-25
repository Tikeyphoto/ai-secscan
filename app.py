import os
import zipfile
import tempfile
import shutil
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, Response
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
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"], storage_uri="memory://")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(BASE_DIR, "scanner", "rules.json")
CVE_FILE = os.path.join(BASE_DIR, "scanner", "cve_db.json")

db_manager.init_db()
scanner = SecurityScanner(RULES_FILE)
sca_scanner = SCAEngine(CVE_FILE)
ai_scanner = AIEngine()

def safe_extract_zip(zip_path, extract_dir):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.infolist():
            if member.filename.startswith('/') or '..' in member.filename:
                continue
            zip_ref.extract(member, extract_dir)

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

@app.route('/')
def index():
    if 'username' not in session: return redirect(url_for('login'))
    user = db_manager.get_user(session['username'])
    if not user: session.clear(); return redirect(url_for('login'))
    return render_template('index.html', user=user)

@app.route('/profile')
def profile():
    if 'username' not in session: return redirect(url_for('login'))
    user = db_manager.get_user(session['username'])
    if not user: session.clear(); return redirect(url_for('login'))
    history = db_manager.get_user_scans(session['username'])
    return render_template('profile.html', user=user, history=history)

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
        if db_manager.create_user(username, generate_password_hash(password)):
            return redirect(url_for('login'))
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
            return redirect(url_for('index'))
        return render_template('login.html', error="Неверный логин или пароль")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/api/scan', methods=['POST'])
@limiter.limit("10 per minute")
def scan():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    username = session['username']
    allowed, scans_left = db_manager.check_and_increment_limit(username)
    if not allowed: return jsonify({"error": "Лимит сканирований исчерпан."}), 403

    allowed_exts = ['.py', '.js', '.php', '.java', '.ts', '.env', '.yml', '.yaml', '.json', '.txt', '.cfg', '.ini']
    filename = "manual_input.py"
    user_baselines = db_manager.get_user_baselines(username)
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
                for f in files:
                    filepath = os.path.join(root, f)
                    rel_path = os.path.relpath(filepath, extract_dir)
                    
                    # --- SCA АНАЛИЗ (requirements.txt) ---
                    if f == 'requirements.txt':
                        with open(filepath, 'r', encoding='utf-8-sig', errors='ignore') as req_file:
                            sca_findings = sca_scanner.scan_requirements(req_file.read())
                            for sca_f in sca_findings:
                                sca_f["file"] = rel_path
                            findings.extend(sca_findings)
                    
                    # --- АНАЛИЗ КОДА ---
                    elif any(f.endswith(ext) for ext in allowed_exts):
                        with open(filepath, 'r', encoding='utf-8-sig', errors='ignore') as code_file:
                            code = code_file.read()
                            
                        file_findings = scanner.scan_code(code, rel_path, user_baselines)
                        for finding in file_findings:
                            if "error" not in finding: finding["file"] = rel_path
                            findings.append(finding)
                            
                        if use_ai and ai_files_processed < 2:
                            ai_findings = ai_scanner.analyze_code(code)
                            for a_f in ai_findings:
                                a_f["file"] = rel_path
                            findings.extend(ai_findings)
                            ai_files_processed += 1
        finally:
            shutil.rmtree(temp_dir)

    elif 'file' in request.files:
        file = request.files['file']
        if not any(file.filename.endswith(ext) for ext in allowed_exts):
            return jsonify({"error": "Разрешены только .py, .js, .php, .java"}), 400
        filename = file.filename
        code = file.read().decode('utf-8-sig')
        
        findings = scanner.scan_code(code, filename, user_baselines)
        if use_ai:
            ai_findings = ai_scanner.analyze_code(code)
            findings.extend(ai_findings)
        for f in findings:
            if "error" not in f: f["file"] = filename

    elif request.is_json and 'code' in request.json:
        code = request.json['code']
        findings = scanner.scan_code(code, filename, user_baselines)
        if use_ai:
            ai_findings = ai_scanner.analyze_code(code)
            findings.extend(ai_findings)
        for f in findings:
            if "error" not in f: f["file"] = filename
    else:
        return jsonify({"error": "Не передан код или файл"}), 400

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
    is_only_syntax_error = (len(findings) == 1 and "error" in findings[0])
    if not is_only_syntax_error:
        db_manager.save_scan_report(username, filename, findings)
    
    return jsonify({
        "status": "success", 
        "filename": filename, 
        "findings": findings, 
        "scans_left": scans_left
    })

@app.route('/api/last_scan', methods=['GET'])
def last_scan():
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    filename, findings = db_manager.get_last_scan_report(session['username'])
    if not filename: return jsonify({"status": "empty"})
    return jsonify({"status": "success", "filename": filename, "findings": findings})

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

@app.route('/api/report/<format>', methods=['GET'])
def download_report(format):
    if 'username' not in session: return jsonify({"error": "Не авторизован"}), 401
    filename, findings = db_manager.get_last_scan_report(session['username'])
    if not filename: return "Сначала выполните сканирование", 400
        
    if format == 'json':
        report = ReportGenerator.generate_json(findings, filename)
        return Response(report, mimetype='application/json', headers={'Content-Disposition': f'attachment;filename=report.json'})
    elif format == 'sarif':
        report = ReportGenerator.generate_sarif(findings, filename)
        return Response(report, mimetype='application/json', headers={'Content-Disposition': f'attachment;filename=report.sarif'})
    elif format == 'pdf':
        pdf_bytes = ReportGenerator.generate_pdf(findings, filename)
        return Response(pdf_bytes, mimetype='application/pdf', headers={'Content-Disposition': f'attachment;filename=report.pdf'})
    return "Неверный формат", 400

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)