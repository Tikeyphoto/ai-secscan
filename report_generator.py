import json
from fpdf import FPDF
from datetime import datetime
import os

# Load rules for compliance mapping
_rules_path = os.path.join(os.path.dirname(__file__), "scanner", "rules.json")
try:
    with open(_rules_path, encoding="utf-8-sig") as _f:
        SCANNER_RULES = json.load(_f)
except Exception as e:
    print(f"[report] Failed to load rules.json: {e}", flush=True)
    SCANNER_RULES = []


class ReportGenerator:
    @staticmethod
    def generate_json(findings, filename, score, grade):
        report = {
            "meta": {"tool": "AI-SecScan", "version": "1.0", "timestamp": datetime.now().isoformat(), "target_file": filename},
            "security_score": {"score": score, "grade": grade},
            "summary": {
                "total_issues": len(findings),
                "critical": sum(1 for f in findings if f.get('severity') == 'CRITICAL'),
                "high": sum(1 for f in findings if f.get('severity') == 'HIGH'),
                "medium": sum(1 for f in findings if f.get('severity') == 'MEDIUM')
            },
            "findings": [{**f, "compliance": next((r["compliance"] for r in SCANNER_RULES if r["id"] == f.get("rule_id")), {})} for f in findings]
        }
        return json.dumps(report, ensure_ascii=False, indent=4)

    @staticmethod
    def generate_sarif(findings, filename, score, grade):
        results = []
        for f in findings:
            level = "warning"
            if f.get('severity') in ['CRITICAL', 'HIGH']: level = "error"
            elif f.get('severity') == 'MEDIUM': level = "warning"
            else: level = "note"

            result = {
                "ruleId": f.get('rule_id', 'UNKNOWN'),
                "message": {"text": f.get('message', 'Уязвимость')},
                "level": level,
                "properties": {"compliance": next((r["compliance"] for r in SCANNER_RULES if r["id"] == f.get("rule_id")), {})},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get('file', filename)},
                        "region": {"startLine": f.get('line', 1), "snippet": {"text": f.get('code', '')}}
                    }
                }]
            }
            results.append(result)

        sarif_report = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "AI-SecScan", "version": "1.0.0", "informationUri": "https://example.com"}},
                "properties": {"security_score": score, "grade": grade},
                "results": results
            }]
        }
        return json.dumps(sarif_report, ensure_ascii=False, indent=4)

    @staticmethod
    def generate_pdf(findings, filename, score, grade):
        pdf = FPDF()
        pdf.set_auto_page_break(auto=False)  # Отключаем авто-разрыв для обложки
        font_dir = os.path.join(os.path.dirname(__file__), 'fonts')
        pdf.add_font('Arial', '', os.path.join(font_dir, 'arial.ttf'), uni=True)
        pdf.add_font('Arial', 'B', os.path.join(font_dir, 'arialbd.ttf'), uni=True)

        # ==========================================
        # СТРАНИЦА 1: ОБЛОЖКА
        # ==========================================
        pdf.add_page()
        pdf.set_fill_color(15, 15, 30)  # Тёмно-синий фон
        pdf.rect(0, 0, 210, 297, 'F')  # A4

        # Логотип (текстовый, в верхней части)
        pdf.set_font("Arial", "B", 28)
        pdf.set_text_color(99, 102, 241)  # Индиго
        pdf.set_y(60)
        pdf.cell(0, 20, "AI-SecScan", ln=True, align="C")

        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(200, 200, 200)
        pdf.cell(0, 10, "Static Application Security Testing", ln=True, align="C")

        # Большая буква оценки в центре
        pdf.set_y(120)
        grade_color = (34, 197, 94) if grade in ['A', 'B'] else (245, 158, 11) if grade == 'C' else (239, 68, 68)
        pdf.set_fill_color(*grade_color)
        pdf.set_draw_color(*grade_color)
        pdf.set_line_width(2)
        pdf.circle(x=105, y=150, r=30, style='DF')
        
        pdf.set_font("Arial", "B", 48)
        pdf.set_text_color(255, 255, 255)
        pdf.set_y(138)
        pdf.cell(0, 25, grade, ln=True, align="C")

        # Название проекта
        pdf.set_y(200)
        pdf.set_font("Arial", "B", 18)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 10, "Security Report", ln=True, align="C")

        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(180, 180, 180)
        pdf.cell(0, 8, f"Project: {filename}", ln=True, align="C")
        pdf.cell(0, 8, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}", ln=True, align="C")

        # Подвал на обложке
        pdf.set_y(250)
        pdf.set_font("Arial", "", 10)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(0, 8, "https://aisecscan.by  |  info@aisecscan.by", ln=True, align="C")

        # ==========================================
        # СТРАНИЦА 2: EXECUTIVE SUMMARY
        # ==========================================
        pdf.set_auto_page_break(auto=True, margin=15)  # Включаем для контента
        pdf.add_page()
        pdf.set_text_color(0, 0, 0)

        # Заголовок раздела
        pdf.set_font("Arial", "B", 20)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 15, "Executive Summary", ln=True)
        pdf.set_draw_color(99, 102, 241)
        pdf.set_line_width(0.5)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(8)

        # Подсчёты
        critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        high = sum(1 for f in findings if f.get('severity') == 'HIGH')
        medium = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
        low = sum(1 for f in findings if f.get('severity') == 'LOW')

        # Карточки со статистикой (4 в ряд)
        pdf.set_font("Arial", "B", 10)
        
        # Critical (красный)
        pdf.set_fill_color(254, 226, 226)
        pdf.set_text_color(185, 28, 28)
        pdf.cell(45, 25, f"{critical}", 1, 0, "C", True)
        
        # High (оранжевый)
        pdf.set_fill_color(254, 215, 170)
        pdf.set_text_color(154, 52, 18)
        pdf.cell(45, 25, f"{high}", 1, 0, "C", True)
        
        # Medium (желтый)
        pdf.set_fill_color(254, 240, 138)
        pdf.set_text_color(133, 77, 14)
        pdf.cell(45, 25, f"{medium}", 1, 0, "C", True)
        
        # Low (серый)
        pdf.set_fill_color(229, 231, 235)
        pdf.set_text_color(75, 85, 99)
        pdf.cell(45, 25, f"{low}", 1, 1, "C", True)

        # Подписи под карточками
        pdf.set_font("Arial", "", 8)
        pdf.set_text_color(100, 100, 100)
        pdf.set_y(pdf.get_y() + 2)
        pdf.cell(45, 5, "CRITICAL", 0, 0, "C")
        pdf.cell(45, 5, "HIGH", 0, 0, "C")
        pdf.cell(45, 5, "MEDIUM", 0, 0, "C")
        pdf.cell(45, 5, "LOW", 0, 1, "C")
        pdf.ln(12)

        # Описание оценки
        pdf.set_font("Arial", "B", 14)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 10, f"Security Score: {score}/100 (Grade {grade})", ln=True)
        pdf.ln(3)

        # Комментарий по оценке
        grade_comment = {
            'A': "Excellent security posture. The code passes most security checks and follows best practices.",
            'B': "Good security posture. Minor improvements recommended but no critical issues found.",
            'C': "Moderate security posture. Several issues require attention to prevent future risks.",
            'D': "Poor security posture. Multiple high-severity issues found. Immediate action recommended.",
            'F': "Critical security posture. Multiple critical vulnerabilities found. Do not deploy to production."
        }.get(grade, "Unknown security grade.")

        pdf.set_font("Arial", "", 11)
        pdf.set_text_color(75, 85, 99)
        pdf.multi_cell(0, 6, grade_comment)
        pdf.ln(10)

        # Топ-3 правила по количеству находок
        pdf.set_font("Arial", "B", 12)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 10, "Top Issues", ln=True)
        pdf.set_font("Arial", "", 10)
        pdf.set_text_color(75, 85, 99)

        from collections import Counter
        rule_counts = Counter(f.get('rule_id', 'UNKNOWN') for f in findings)
        for rule, count in rule_counts.most_common(5):
            pdf.cell(0, 6, f"  - {rule}: {count} occurrence(s)", ln=True)
        pdf.ln(10)

        # Compliance блок
        pdf.set_font("Arial", "B", 12)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 10, "Compliance Mapping", ln=True)
        pdf.set_font("Arial", "", 10)
        pdf.set_text_color(75, 85, 99)

        owasp_set = set()
        cwe_set = set()
        for f in findings:
            comp = next((r["compliance"] for r in SCANNER_RULES if r["id"] == f.get("rule_id")), {})
            if comp.get('owasp'): owasp_set.add(comp['owasp'])
            if comp.get('cwe'): cwe_set.add(comp['cwe'])

        pdf.cell(0, 6, f"OWASP Top 10 categories affected: {', '.join(sorted(owasp_set)) or 'None'}", ln=True)
        pdf.cell(0, 6, f"CWE IDs affected: {', '.join(sorted(cwe_set)) or 'None'}", ln=True)
        pdf.ln(10)

        pdf.set_font("Arial", "", 9)
        pdf.set_text_color(120, 120, 120)
        pdf.multi_cell(0, 5, "Note: Results are generated automatically and are advisory in nature. "
                            "Manual verification by a security specialist is recommended before making "
                            "critical decisions.")

        # ==========================================
        # СТРАНИЦА 3+: ДЕТАЛИ (таблица)
        # ==========================================
        pdf.add_page()
        pdf.set_text_color(0, 0, 0)

        pdf.set_font("Arial", "B", 16)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 12, "Detailed Findings", ln=True)
        pdf.set_draw_color(99, 102, 241)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)

        # Заголовки таблицы
        pdf.set_font("Arial", "B", 9)
        pdf.set_fill_color(15, 23, 42)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(18, 8, "Severity", 1, 0, "C", True)
        pdf.cell(32, 8, "Rule", 1, 0, "C", True)
        pdf.cell(10, 8, "Line", 1, 0, "C", True)
        pdf.cell(40, 8, "Compliance", 1, 0, "C", True)
        pdf.cell(90, 8, "Code / File", 1, 1, "C", True)

        # Строки таблицы
        pdf.set_font("Arial", "", 8)
        for f in findings:
            code_snippet = str(f.get('code', ''))
            if len(code_snippet) > 45: code_snippet = code_snippet[:45] + "..."

            file_info = f"{f.get('file', filename)}"
            if len(file_info) > 30: file_info = "..." + file_info[-30:]

            display_text = f"{file_info}: {code_snippet}"

            # Цвет по severity
            severity = f.get('severity', 'N/A')
            if severity == 'CRITICAL': pdf.set_text_color(185, 28, 28)
            elif severity == 'HIGH': pdf.set_text_color(200, 100, 0)
            elif severity == 'MEDIUM': pdf.set_text_color(133, 100, 14)
            elif severity in ('AI', 'LOW'): pdf.set_text_color(99, 102, 241)
            else: pdf.set_text_color(0, 0, 0)

            comp = next((r["compliance"] for r in SCANNER_RULES if r["id"] == f.get("rule_id")), {})
            comp_str = f"{comp.get('cwe','')} / {comp.get('owasp','')}" if comp else ""

            pdf.cell(18, 7, str(severity)[:8], 1, 0, "C")
            pdf.set_text_color(0, 0, 0)
            pdf.cell(32, 7, str(f.get('rule_id', 'N/A'))[:14], 1, 0, "C")
            pdf.cell(10, 7, str(f.get('line', '')), 1, 0, "C")
            pdf.cell(40, 7, comp_str[:18], 1, 0, "C")
            pdf.cell(90, 7, display_text[:55], 1, 1, "L")

        # ==========================================
        # FOOTER на каждой странице
        # ==========================================
        total_pages = pdf.page_no()
        pdf.set_auto_page_break(auto=False)  # ОТКЛЮЧАЕМ авто-перенос для футера
        for page_num in range(1, total_pages + 1):
            pdf.page = page_num
            pdf.set_y(-15)  # -15 мм от нижнего края (правильный способ)
            pdf.set_font("Arial", "", 8)
            pdf.set_text_color(150, 150, 150)
            pdf.cell(0, 5, f"AI-SecScan | Confidential Security Report | Page {page_num} of {total_pages}", 0, 0, "C")

        return bytes(pdf.output())