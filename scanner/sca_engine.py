import json
import os
import re
from packaging import version
import xml.etree.ElementTree as ET

class SCAEngine:
    def __init__(self, cve_db_path):
        with open(cve_db_path, 'r', encoding='utf-8-sig') as f:
            self.cve_db = json.load(f)

    def _clean_version(self, v_str):
        """Убирает ^ ~ >= < v и оставляет только цифры и точки."""
        if not v_str:
            return None
        v_str = re.sub(r'[\^~>=<v\s]', '', str(v_str))
        # Для Java (1.2.3.RELEASE) берем первую числовую часть
        match = re.match(r'^(\d+(?:\.\d+)*)', v_str)
        return match.group(1) if match else None

    def _check_package(self, pkg_name, pkg_version_str, line_num):
        findings = []
        clean_v = self._clean_version(pkg_version_str)
        if not clean_v:
            return findings

        try:
            v_parsed = version.parse(clean_v)
        except Exception:
            return findings

        for cve in self.cve_db:
            if cve['package'].lower() == pkg_name.lower():
                try:
                    vuln_below = self._clean_version(cve['vulnerable_below'])
                    if vuln_below and v_parsed < version.parse(vuln_below):
                        findings.append({
                            "id": f"SCA_{cve['cve']}_{pkg_name}",
                            "rule_id": "SCA_VULNERABLE_DEP",
                            "severity": "CRITICAL",
                            "message": f"[{cve['cve']}] {cve['message']}",
                            "line": line_num,
                            "code": f"{pkg_name}@{pkg_version_str} (Требуется >= {cve['vulnerable_below']})",
                            "weight": 1.0,
                            "compliance": cve.get("compliance", {})
                        })
                except Exception:
                    pass
        return findings

    def scan_requirements(self, content: str) -> list:
        findings = []
        for line_num, line in enumerate(content.split('\n'), 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            match = re.match(r'^([a-zA-Z0-9_\-]+)\s*==\s*([0-9a-zA-Z\.\-]+)', line)
            if match:
                findings.extend(self._check_package(match.group(1), match.group(2), line_num))
        return findings

    def scan_package_json(self, content: str) -> list:
        findings = []
        try:
            data = json.loads(content)
            deps = {}
            deps.update(data.get("dependencies", {}))
            deps.update(data.get("devDependencies", {}))
            for pkg, ver in deps.items():
                findings.extend(self._check_package(pkg, ver, 1))
        except Exception:
            pass
        return findings

    def scan_go_mod(self, content: str) -> list:
        findings = []
        for line_num, line in enumerate(content.split('\n'), 1):
            line = line.strip()
            if not line or line.startswith('//') or line.startswith('module ') or line.startswith('go ') or line.startswith(')'):
                continue
            # require github.com/gin-gonic/gin v1.8.0
            match = re.match(r'^(?:require\s+)?([^\s]+)\s+(v?[0-9][^\s]+)', line)
            if match:
                findings.extend(self._check_package(match.group(1), match.group(2), line_num))
        return findings

    def scan_pom_xml(self, content: str) -> list:
        findings = []
        try:
            # Убираем namespace, чтобы упростить поиск
            content_clean = re.sub(r'xmlns="[^"]+"', '', content)
            root = ET.fromstring(content_clean)
            for dep in root.findall(".//dependency"):
                group = dep.findtext("groupId")
                artifact = dep.findtext("artifactId")
                ver = dep.findtext("version")
                if group and artifact and ver and not ver.startswith('${'):
                    # Ищем по artifactId (например, log4j-core, spring-core)
                    findings.extend(self._check_package(artifact, ver, 1))
                    # И по groupId:artifactId
                    findings.extend(self._check_package(f"{group}:{artifact}", ver, 1))
        except Exception:
            pass
        return findings
