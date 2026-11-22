FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
# Łatki pakietow systemowych z repozytorium bezpieczenstwa Debiana (m.in. zlib1g - CVE-2026-85091)
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
# Podbicie pip i setuptools (CVE-2025-47273); usuniecie zapasowych wheeli z ensurepip,
# ktore zawieraja stara wersje setuptools i nie sa potrzebne w obrazie
RUN pip install --no-cache-dir --upgrade pip setuptools \
    && pip install --no-cache-dir -r requirements.txt \
    && rm -rf /usr/local/lib/python3.12/ensurepip \
    && find / -xdev \( -name 'setuptools-*.whl' -o -name 'pip-*.whl' \) -delete \
    && useradd --create-home --uid 10001 cyberdesk
COPY . .
USER cyberdesk
EXPOSE 5000
ENTRYPOINT ["sh", "entrypoint.sh"]
CMD ["python", "-m", "gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--access-logfile", "-", "app:app"]
