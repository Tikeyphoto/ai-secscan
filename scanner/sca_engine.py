import json
import os
import re
from packaging import version

class SCAEngine:
    def __init__(self, cve_db_path):
        with open(cve_db_path, 'r', encoding='utf-8-sig') as f:
            self.cve_db = json.load(f)

    def scan_requirements(self, content: str) -> list:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            # Парсим строку вида "flask==2.0.1" или "requests>=2.0"
            match = re.match(r'^([a-zA-Z0-9_\-]+)\s*==\s*([0-9a-zA-Z\.\-]+)', line)
            if match:
                pkg_name = match.group(1).lower()
                pkg_version = match.group(2)
                
                for cve in self.cve_db:
                    if cve['package'].lower() == pkg_name:
                        try:
                            # Сравниваем версии (например, 2.0.1 < 3.0.0)
                            if version.parse(pkg_version) < version.parse(cve['vulnerable_below']):
                                findings.append({
                                    "id": f"SCA_{cve['cve']}_{pkg_name}",
                                    "rule_id": "SCA_VULNERABLE_DEP",
                                    "severity": "CRITICAL",
                                    "message": f"[{cve['cve']}] {cve['message']}",
                                    "line": line_num,
                                    "code": f"{pkg_name}=={pkg_version} (Требуется >= {cve['vulnerable_below']})",
                                    "weight": 1.0
                                })
                        except Exception:
                            pass # Ошибка парсинга версии - пропускаем
        return findings