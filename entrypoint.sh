#!/bin/sh
# ==============================================================================
# CyberDesk Container Entrypoint
# Used by: BOTH Legacy Self-Hosted (docker-compose.yml) AND Cloud (AWS EC2 / RDS)
#
# Execution Flow:
#   Dockerfile ENTRYPOINT -> entrypoint.sh -> scripts/bootstrap_db.py -> Gunicorn
#
# Security Goal (Least Privilege):
#   The web server should NEVER hold credentials capable of dropping or altering
#   database tables (DDL). This script runs schema setup with the owner password,
#   erases that password from the environment, and launches the web server with
#   a restricted DML-only (SELECT/INSERT/UPDATE/DELETE) database user.
# ==============================================================================

# Fail-fast safety flags for POSIX sh (python:3.12-slim uses dash/sh, not bash):
#   -e : Exit immediately if any command returns a non-zero exit code (e.g., if
#        the database is unreachable or bootstrap_db.py crashes).
#   -u : Treat unset environment variables as an immediate error.
set -eu

# ------------------------------------------------------------------------------
# STEP 1: Validate Required Secrets & Bootstrap Database (High-Privilege Phase)
# ------------------------------------------------------------------------------
# `${VAR:?message}` exits immediately with a clear error if VAR is unset OR an
# empty string (""), catching misconfigurations before attempting a DB connection.
#
# Runs scripts/bootstrap_db.py to create/migrate tables and ensure the restricted
# runtime user exists. Works identically on local Docker Postgres and AWS RDS
# (where PostgreSQL's /docker-entrypoint-initdb.d/db-init.sh never runs).
#
# Shell Detail:
#   Setting `DB_USER=... DB_PASS=...` inline BEFORE the command passes those
#   variables ONLY to the `python scripts/bootstrap_db.py` child process.
#   They are NOT exported to the rest of this script.
#   `${ADMIN_DB_USER:-cyberdesk}` uses ADMIN_DB_USER if set, else defaults to "cyberdesk".
DB_USER="${ADMIN_DB_USER:-cyberdesk}" \
DB_PASS="${ADMIN_DB_PASS:?ADMIN_DB_PASS is required}" \
APP_DB_PASS="${APP_DB_PASS:?APP_DB_PASS is required}" \
  python scripts/bootstrap_db.py

# ------------------------------------------------------------------------------
# STEP 2: Drop Database Privileges (Runtime Phase)
# ------------------------------------------------------------------------------
# Export the restricted runtime credentials that Flask (app.py) will read via
# os.environ['DB_USER'] and os.environ['DB_PASS'] when handling HTTP requests.
export DB_USER="${APP_DB_USER:-cyberdesk_app}"
export DB_PASS="$APP_DB_PASS"

# CRITICAL SECURITY STEP:
# Remove the database owner's password (and the now-redundant APP_DB_PASS) from
# the shell environment BEFORE launching Gunicorn. Even if an attacker achieved
# Remote Code Execution (RCE) inside Flask and dumped `os.environ`, they would
# NOT find ADMIN_DB_PASS and could not DROP tables or alter the database schema.
unset ADMIN_DB_PASS APP_DB_PASS

# ------------------------------------------------------------------------------
# STEP 3: Hand Off to the Web Server as PID 1
# ------------------------------------------------------------------------------
# "$@" expands to the Dockerfile's CMD (`python -m gunicorn --bind 0.0.0.0:5000 ...`).
#
# Why `exec` matters:
#   Without `exec`, `/bin/sh` stays alive as PID 1 and Gunicorn runs as a child
#   process. When Docker or AWS stops the container (e.g., during a rolling deploy),
#   it sends SIGTERM to PID 1. `/bin/sh` does not forward SIGTERM to children,
#   causing dropped requests and a forced SIGKILL after 10 seconds.
#   `exec` REPLACES the shell process with Gunicorn, making Gunicorn PID 1 so it
#   receives SIGTERM directly and finishes in-flight HTTP requests gracefully.
exec "$@"












