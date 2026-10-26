"""scan_core.py — чистое ядро сканирования (без Flask).

Используется и в app.py (синхронный режим), и в tasks.py (Celery).
"""
import os
import tempfile
import shutil
import json
import zipfile

from scanner.engine import SecurityScanner
from scanner.sca_engine import SCAEngine
from scanner.ai_engine import AIEngine
from sbom_generator import SBOMGenerator
import db_manager

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(BASE_DIR, "scanner", "rules.json")
CVE_FILE = os.path.join(BASE_DIR, "scanner", "cve_db.json")

scanner = SecurityScanner(RULES_FILE)
sca_scanner = SCAEngine(CVE_FILE)
ai_scanner = AIEngine()

ALLOWED_EXTS = ['.py', '.js', '.php', '.java', '.ts', '.env', '.yml', '.yaml',
                '.json', '.txt', '.cfg', '.ini', '.xml']


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


def process_scan(username, filename, code, use_ai, user_baselines, custom_rules):
    findings = scanner.scan_code(code, filename, user_baselines, custom_rules)
    if use_ai:
        ai_findings = ai_scanner.analyze_code(code)
        findings.extend(ai_findings)
    for f in findings:
        if "error" not in f: f["file"] = filename
    return findings



def scan_zip(username, zip_path, filename, use_ai=False):
    """Полный скан ZIP-проекта. Возвращает (findings, score, grade).

    Аналог ZIP-ветки /api/scan, без Flask.
    """
    user_baselines = db_manager.get_user_baselines(username)
    custom_rules = db_manager.get_custom_rules(username)
    findings = []
    temp_dir = tempfile.mkdtemp()

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

                if f == 'requirements.txt':
                    with open(filepath, 'r', encoding='utf-8-sig', errors='ignore') as req_file:
                        req_content = req_file.read()
                    sca_findings = sca_scanner.scan_requirements(req_content)
                    for sca_f in sca_findings:
                        sca_f["file"] = rel_path
                    findings.extend(sca_findings)
                    sbom_data = SBOMGenerator.generate_cyclonedx(req_content, filename)
                    db_manager.save_sbom(username, filename, sbom_data)
                elif any(f.endswith(ext) for ext in ALLOWED_EXTS) or f.lower() == 'dockerfile':
                    with open(filepath, 'r', encoding='utf-8-sig', errors='ignore') as code_file:
                        code = code_file.read()
                    file_findings = scanner.scan_code(code, rel_path, user_baselines, custom_rules)
                    for finding in file_findings:
                        if "error" not in finding:
                            finding["file"] = rel_path
                        findings.append(finding)
                    if use_ai and ai_files_processed < 2:
                        ai_findings = ai_scanner.analyze_code(code)
                        for a_f in ai_findings:
                            a_f["file"] = rel_path
                        findings.extend(ai_findings)
                        ai_files_processed += 1
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    # дедупликация
    unique = []
    seen = set()
    for f in findings:
        if "error" in f:
            unique.append(f)
            continue
        key = f"{f.get('file')}_{f.get('rule_id')}_{f.get('line')}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    findings = unique

    score, grade = calculate_score(findings)

    if not (len(findings) == 1 and "error" in findings[0]):
        db_manager.save_scan_report(username, filename, findings)

    return findings, score, grade
