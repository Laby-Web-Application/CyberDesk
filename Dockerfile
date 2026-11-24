# ==============================================================================
# CyberDesk Web Application Image
# Used by: BOTH Legacy Self-Hosted (docker-compose.yml) AND Cloud (AWS ECR / EC2)
#
# Purpose: Packages the Python/Flask application and Gunicorn WSGI server into
# a minimal, patched, non-root Linux container image.
# ==============================================================================

# 1. BASE IMAGE
# Start from the official slim Debian-based Python 3.12 image.
# "-slim" strips out compilers and heavy OS tools to keep the image small and
# reduce the attack surface (fewer installed packages = fewer potential CVEs).
FROM python:3.12-slim

# 2. PYTHON RUNTIME ENVIRONMENT VARIABLES
# - PYTHONDONTWRITEBYTECODE=1: Stops Python from writing .pyc cache files to disk.
#   This is CRITICAL because the container runs with a --read-only filesystem in
#   both docker-compose.yml and AWS EC2.
# - PYTHONUNBUFFERED=1: Forces Python stdout/stderr to flush immediately instead
#   of buffering, so logs appear in real time in `docker logs` and AWS SSM output.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# Set the working directory inside the container. All subsequent COPY, RUN,
# ENTRYPOINT, and CMD instructions execute relative to /app.
WORKDIR /app

# 3. OS-LEVEL SECURITY PATCHING (Cloud CI/CD Hardening)
# Pull the latest Debian security patches (e.g., zlib1g CVE-2026-85091) so the
# Trivy container scanner in CI and ECR scan-on-push pass cleanly.
# Deleting /var/lib/apt/lists/* in the same RUN layer prevents cached package
# indexes from bloating the final image size.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# 4. PYTHON DEPENDENCIES & NON-ROOT USER SETUP
# Copy requirements.txt BEFORE the rest of the codebase. Docker caches each
# layer: if you edit app.py without changing requirements.txt, Docker reuses
# this cached layer and skips reinstalling packages (much faster builds).
COPY requirements.txt .

# In a single layer:
# - Upgrade pip and setuptools to patch known CVEs (e.g., CVE-2025-47273).
# - Install pinned app dependencies (Flask, Gunicorn, psycopg2, etc.) without
#   saving a pip cache (--no-cache-dir).
# - Delete ensurepip and any leftover pip/setuptools .whl archives, which often
#   bundle older vulnerable versions that trigger Trivy alerts.
# - Create a dedicated unprivileged Linux user ("cyberdesk", UID 10001) so the
#   web server never runs as root inside the container.
RUN pip install --no-cache-dir --upgrade pip setuptools \
    && pip install --no-cache-dir -r requirements.txt \
    && rm -rf /usr/local/lib/python3.12/ensurepip \
    && find / -xdev \( -name 'setuptools-*.whl' -o -name 'pip-*.whl' \) -delete \
    && useradd --create-home --uid 10001 cyberdesk

# 5. COPY APPLICATION CODE
# Copies project files into /app. Notice there is NO "--chown=cyberdesk" flag:
# files remain owned by root (read-only for UID 10001), adding defense-in-depth
# so even if the app were compromised, it could not overwrite its own source code.
COPY . .

# 6. DROP PRIVILEGES
# Switch from root to the unprivileged "cyberdesk" user for all runtime commands.
USER cyberdesk

# 7. NETWORK DOCUMENTATION
# Documents that Gunicorn listens on TCP port 5000 inside the container.
# (Does not publish the port by itself; -p 5000:5000 in docker run/compose does.)
EXPOSE 5000

# 8. CONTAINER STARTUP CHAIN (ENTRYPOINT + CMD)
# Docker combines these into: `sh entrypoint.sh python -m gunicorn ...`
# - ENTRYPOINT runs first: initializes/migrates the DB as the schema owner,
#   drops the admin password, and switches to the restricted `cyberdesk_app` user.
# - CMD is passed as "$@" to entrypoint.sh, which executes Gunicorn as PID 1:
#     --bind 0.0.0.0:5000  : Listen on all container interfaces on port 5000.
#     --workers 2          : Spawn 2 separate OS worker processes.
#     --threads 4          : Run 4 threads per worker (up to 8 concurrent requests).
#     --access-logfile -   : Stream HTTP access logs to stdout.
#     app:app              : Load the `app` Flask instance from `app.py`.
ENTRYPOINT ["sh", "entrypoint.sh"]
CMD ["python", "-m", "gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--access-logfile", "-", "app:app"]
