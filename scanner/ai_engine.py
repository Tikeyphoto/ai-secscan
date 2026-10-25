import requests
import json
import re
import ast

class AIEngine:
    def __init__(self, model_name="qwen2.5-coder:7b", api_url="http://host.docker.internal:11434/api/generate"):
        self.model_name = model_name
        self.api_url = api_url

    def _chunk_code(self, code: str, max_lines=100):
        """Разбивает код на куски (чанки), чтобы не перегружать нейросеть."""
        chunks = []
        try:
            # Пробуем умную нарезку через AST (по функциям)
            tree = ast.parse(code)
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    chunk = ast.get_source_segment(code, node)
                    if chunk:
                        chunks.append(chunk)
            if chunks:
                return chunks
        except SyntaxError:
            pass # Если код с ошибкой (как is_admin = True), AST не сработает
        
        # Fallback: тупо режем по строкам, если AST не смог
        lines = code.split('\n')
        for i in range(0, len(lines), max_lines):
            chunks.append('\n'.join(lines[i:i+max_lines]))
        return chunks

    def analyze_code(self, code: str):
        print(f"[AI] Анализ файла. Размер: {len(code)} символов.")
        chunks = self._chunk_code(code)
        print(f"[AI] Разбито на {len(chunks)} чанков.")
        
        all_findings = []
        
        # Ограничиваем количество чанков за один раз (чтобы не ждать 10 минут)
        # Для банковских проектов можно поднять лимит, но в MVP оставим 5.
        for i, chunk in enumerate(chunks[:5]):
            print(f"[AI] Анализ чанка {i+1}/{len(chunks[:5])}...")
            
            prompt = f"""Ты — эксперт по безопасности. Проанализируй этот фрагмент кода (Python, JavaScript, PHP или Java).
Ищи логические уязвимости (обход авторизации, небезопасное сравнение, утечка паролей).
Верни ответ СТРОГО в формате JSON-массива (без markdown-разметки).
Формат: [{{"line": 1, "severity": "HIGH", "message": "Описание"}}]
Если уязвимостей нет, верни [].

Код:
{chunk}"""

            payload = {"model": self.model_name, "prompt": prompt, "stream": False}
            
            try:
                response = requests.post(self.api_url, json=payload, timeout=100)
                response_text = response.json().get('response', '').strip()
                cleaned_text = response_text.replace('```json', '').replace('```', '').strip()
                
                match = re.search(r'\[.*\]', cleaned_text, re.DOTALL)
                if match:
                    findings = json.loads(match.group(0))
                    for f in findings:
                        all_findings.append({
                            "id": f"AI_{hash(f.get('message'))}",
                            "rule_id": "AI_LOGIC_FLAW",
                            "severity": f.get("severity", "HIGH").upper(),
                            "message": "[AI] " + f.get("message", "Логическая уязвимость"),
                            "line": f.get("line", 1),
                            "code": "Анализ LLM (чанк)",
                            "weight": 1.0
                        })
            except Exception as e:
                print(f"[AI ERROR] Ошибка в чанке {i+1}: {e}")
                
        print(f"[AI] Итог: найдено {len(all_findings)} уязвимостей.")
        return all_findings