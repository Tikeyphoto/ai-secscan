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
        font_dir = os.path.join(os.path.dirname(__file__), 'fonts')
        pdf.add_font('Arial', '', os.path.join(font_dir, 'arial.ttf'), uni=True)
        pdf.add_font('Arial', 'B', os.path.join(font_dir, 'arialbd.ttf'), uni=True)
        
        pdf.add_page()
        
        # --- Заголовок ---
        pdf.set_font("Arial", "B", 20)
        pdf.set_text_color(41, 128, 185)
        pdf.cell(0, 15, "AI-SecScan: Отчет о безопасности", ln=True, align="C")
        
        pdf.set_font("Arial", "", 10)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 10, f"Файл: {filename}", ln=True, align="C")
        pdf.cell(0, 10, f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        pdf.ln(10)
        
        # --- Блок Оценки Безопасности ---
        pdf.set_fill_color(240, 240, 240)
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 15, f"  Оценка безопасности: {grade} ({score}/100)", ln=True, fill=True)
        pdf.ln(10)
        
        # --- Сводка ---
        critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        high = sum(1 for f in findings if f.get('severity') == 'HIGH')
        
        pdf.set_font("Arial", "B", 14)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, f"Найдено проблем: {len(findings)}", ln=True)
        
        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(200, 0, 0)
        pdf.cell(0, 8, f"Критических (Critical): {critical}", ln=True)
        pdf.set_text_color(200, 150, 0)
        pdf.cell(0, 8, f"Высоких (High): {high}", ln=True)
        pdf.ln(10)
        
        # --- Таблица ---
        pdf.set_font("Arial", "B", 10)
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(20, 10, "Уровень", 1, 0, "C", True)
        pdf.cell(35, 10, "Правило", 1, 0, "C", True)
        pdf.cell(10, 10, "Стр.", 1, 0, "C", True)
        pdf.cell(45, 10, "Compliance", 1, 0, "C", True)
        pdf.cell(80, 10, "Код / Файл", 1, 1, "C", True)
        
        pdf.set_font("Arial", "", 9)
        for f in findings:
            code_snippet = str(f.get('code', ''))
            if len(code_snippet) > 50: code_snippet = code_snippet[:50] + "..."
            
            file_info = f"{f.get('file', filename)}"
            if len(file_info) > 25: file_info = "..." + file_info[-25:]
            
            display_text = f"{file_info}: {code_snippet}"
            
            if f.get('severity') == 'CRITICAL': pdf.set_text_color(200, 0, 0)
            elif f.get('severity') == 'HIGH': pdf.set_text_color(200, 150, 0)
            elif f.get('severity') == 'MEDIUM': pdf.set_text_color(150, 150, 0)
            elif f.get('severity') == 'AI': pdf.set_text_color(150, 0, 150)
            else: pdf.set_text_color(0, 0, 0)
            
            # Цвет для AI
            if f.get('rule_id') == 'AI_LOGIC_FLAW': pdf.set_text_color(150, 0, 200)
            
            comp = next((r["compliance"] for r in SCANNER_RULES if r["id"] == f.get("rule_id")), {})
            comp_str = f"{comp.get('cwe','')} / {comp.get('owasp','')}" if comp else ""

            pdf.cell(20, 10, str(f.get('severity', 'N/A'))[:8], 1, 0, "C")
            pdf.set_text_color(0, 0, 0)
            pdf.cell(35, 10, str(f.get('rule_id', 'N/A'))[:14], 1, 0, "C")
            pdf.cell(10, 10, str(f.get('line', '')), 1, 0, "C")
            pdf.cell(45, 10, comp_str[:18], 1, 0, "C")
            pdf.cell(80, 10, display_text[:40], 1, 1, "L")
            
        return bytes(pdf.output())