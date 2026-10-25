import requests
import json
import re
import ast
import os

class AIEngine:
    def __init__(self, model_name="qwen2.5-coder:7b"):
        self.model_name = model_name
        self.api_url = os.environ.get("OLLAMA_API_URL", "http://host.docker.internal:11434/api/generate")

    def _chunk_code(self, code: str, max_lines=100):
        chunks = []
        try:
            tree = ast.parse(code)
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    chunk = ast.get_source_segment(code, node)
                    if chunk: chunks.append(chunk)
            if chunks: return chunks
        except SyntaxError:
            pass
        lines = code.split('\n')
        for i in range(0, len(lines), max_lines):
            chunks.append('\n'.join(lines[i:i+max_lines]))
        return chunks

    def analyze_code(self, code: str):
        chunks = self._chunk_code(code)
        all_findings = []
        
        for i, chunk in enumerate(chunks[:5]):
            prompt = f"""Ты — эксперт по безопасности. Проанализируй этот фрагмент кода.
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
                
        return all_findings

    def stream_fix(self, code: str, issue: str, filename: str = "unknown.py"):
        """Генератор, который отдает кусочки кода по мере их генерации."""
        prompt = f"""Ты — эксперт по безопасности. В файле "{filename}" найдена уязвимость: {issue}.
Перепиши ТОЛЬКО этот фрагмент кода, чтобы исправить уязвимость.
Учти контекст файла. Если это .env файл, предложи безопасный способ хранения секретов (например, удалить строку).
Верни ТОЛЬКО безопасный код, без markdown-разметки (никаких ```), без объяснений и комментариев.
Код:
{code}"""
        payload = {"model": self.model_name, "prompt": prompt, "stream": True}
        
        try:
            response = requests.post(self.api_url, json=payload, stream=True, timeout=100)
            for line in response.iter_lines():
                if line:
                    decoded = json.loads(line.decode('utf-8'))
                    chunk = decoded.get('response', '')
                    if chunk:
                        yield chunk
        except Exception as e:
            yield f"\n// Ошибка AI: {e}"