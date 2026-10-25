FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
COPY fonts /app/fonts
RUN mkdir -p /app/data
EXPOSE 8000
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# ВАЖНО: 1 воркер и таймаут 120 секунд для предотвращения падений SQLite
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "--timeout", "600", "app:app"]