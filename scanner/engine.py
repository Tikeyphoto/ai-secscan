import ast
import json
import os
import hashlib
import re
import db_manager

class SecurityScanner:
    def __init__(self, rules_path: str):
        with open(rules_path, 'r', encoding='utf-8-sig') as f:
            self.rules = json.load(f)
        
    def _generate_hash(self, rule_id: str, code: str) -> str:
        raw = f"{rule_id}|{code}"
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]

    def scan_code(self, code: str, filename: str, user_baselines: dict = None, custom_rules: list = None) -> list:
        findings = []
        ext = os.path.splitext(filename)[1].lower()
        
        # Если это Dockerfile (нет расширения или имя Dockerfile)
        is_dockerfile = filename.lower() == 'dockerfile' or filename.lower().endswith('.dockerfile')
        
        if ext == '.py':
            # Для Python используем AST
            try:
                tree = ast.parse(code)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        func_name = self._get_func_name(node.func)
                        for rule in self.rules:
                            if rule.get("type") == "function_call" and rule["pattern"] == func_name:
                                self._add_finding(findings, rule, code, node.lineno, user_baselines)
                            elif rule.get("type") == "ast_call_check_sql" and rule["pattern"] == func_name:
                                if node.args and isinstance(node.args[0], (ast.JoinedStr, ast.Call)):
                                    self._add_finding(findings, rule, code, node.lineno, user_baselines)
            except SyntaxError as e:
                findings.append({"error": f"Ошибка синтаксиса Python: {e}"})
        else:
            # Для JS, PHP, Dockerfile и т.д. используем Regex (построчно)
            lines = code.split('\n')
            for line_num, line in enumerate(lines, 1):
                for rule in self.rules:
                    if rule.get("type") == "regex":
                        flags = re.IGNORECASE if rule.get("ignore_case") else 0
                        if re.search(rule["pattern"], line, flags):
                            self._add_finding(findings, rule, code, line_num, user_baselines)
                            
        # Пользовательские правила (Custom Rules)
        if custom_rules:
            lines = code.split('\n')
            for line_num, line in enumerate(lines, 1):
                for c_rule in custom_rules:
                    try:
                        if re.search(c_rule['pattern'], line):
                            self._add_finding(findings, {
                                "id": c_rule['rule_id'],
                                "severity": c_rule['severity'],
                                "message": "[CUSTOM] " + c_rule['message']
                            }, code, line_num, user_baselines)
                    except Exception:
                        pass # Игнорируем битые регулярки клиента

        return findings

    def _get_func_name(self, node) -> str:
        if isinstance(node, ast.Name): return node.id
        elif isinstance(node, ast.Attribute): return f"{self._get_func_name(node.value)}.{node.attr}"
        return ""

    def _add_finding(self, findings: list, rule: dict, code: str, line: int, user_baselines: dict = None):
        lines = code.split('\n')
        code_snippet = lines[line-1].strip() if line <= len(lines) else "N/A"
        weight = db_manager.get_weight(rule['id'])
        finding_hash = self._generate_hash(rule['id'], code_snippet)
        if user_baselines and finding_hash in user_baselines: weight = 0.0
        
        findings.append({
            "id": finding_hash, "rule_id": rule['id'], "severity": rule['severity'],
            "message": rule['message'], "line": line, "code": code_snippet, "weight": weight
        })