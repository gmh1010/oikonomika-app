# Oikonomika web app. Runs as a non-root user on a read-only filesystem (see compose file).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin app
WORKDIR /app

COPY app/requirements.txt .
RUN pip install -r requirements.txt

COPY app/ .
RUN rm -rf tests run_dev.py .env .pytest_cache __pycache__ \
 && python -m compileall -q . \
 && chown -R root:root /app && chmod -R a-w /app

USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)" || exit 1
# No gunicorn access log: the app logs method/path/status only (no query strings, no IPs).
CMD ["gunicorn", "--workers", "3", "--threads", "4", "--worker-class", "gthread", "--bind", "0.0.0.0:8000", \
     "--worker-tmp-dir", "/dev/shm", "--timeout", "90", "--graceful-timeout", "20", "--forwarded-allow-ips", "*", "wsgi:app"]
