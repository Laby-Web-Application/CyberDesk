"""Idempotent database bootstrap, run by entrypoint.sh as the schema owner before the app starts.

Works the same against the local Docker Postgres (docker compose) and AWS RDS, where db-init.sh
never runs. It:
  1. takes a Postgres advisory lock, so several containers/instances starting at once
     (e.g. an Auto Scaling Group) do not race each other,
  2. creates/migrates the schema (app.init_db) and optionally seeds demo data,
  3. creates or updates the restricted runtime role (default: cyberdesk_app) and grants it
     only SELECT/INSERT/UPDATE/DELETE - least privilege, the app never runs as the owner.
"""
import os
import sys
from pathlib import Path

import psycopg2
from psycopg2 import sql

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

LOCK_ID = 74210001  # arbitrary, constant for this application


def connect():
    return psycopg2.connect(
        host=os.environ.get('DB_HOST', 'localhost'),
        dbname=os.environ.get('DB_NAME', 'vulntrack'),
        user=os.environ['DB_USER'],
        password=os.environ['DB_PASS'],
        connect_timeout=10,
    )


def ensure_app_role(cur, owner, app_user, app_password, dbname):
    cur.execute('SELECT 1 FROM pg_roles WHERE rolname=%s', (app_user,))
    verb = 'ALTER' if cur.fetchone() else 'CREATE'
    # psycopg2 interpolates the password client-side as a properly quoted literal.
    cur.execute(sql.SQL(verb + ' ROLE {} WITH LOGIN PASSWORD %s').format(sql.Identifier(app_user)), (app_password,))
    role, owner_role = sql.Identifier(app_user), sql.Identifier(owner)
    for statement in (
        sql.SQL('GRANT CONNECT ON DATABASE {} TO {}').format(sql.Identifier(dbname), role),
        sql.SQL('GRANT USAGE ON SCHEMA public TO {}').format(role),
        sql.SQL('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}').format(role),
        sql.SQL('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}').format(role),
        sql.SQL('ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}').format(owner_role, role),
        sql.SQL('ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {}').format(owner_role, role),
    ):
        cur.execute(statement)
    return verb


def main():
    owner = os.environ['DB_USER']
    app_user = os.environ.get('APP_DB_USER', 'cyberdesk_app')
    app_password = os.environ['APP_DB_PASS']
    dbname = os.environ.get('DB_NAME', 'vulntrack')

    conn = connect()
    conn.autocommit = True
    cur = conn.cursor()
    print('bootstrap: waiting for advisory lock', flush=True)
    cur.execute('SELECT pg_advisory_lock(%s)', (LOCK_ID,))
    try:
        from app import app, init_db, seed_demo  # imported late: the app reads env at import time
        with app.app_context():
            init_db()
            if os.environ.get('DEMO_MODE') == '1':
                seed_demo()
        verb = ensure_app_role(cur, owner, app_user, app_password, dbname)
        state = 'created' if verb == 'CREATE' else 'updated'
        print(f'bootstrap: schema ready, role {app_user} {state}', flush=True)
    finally:
        cur.execute('SELECT pg_advisory_unlock(%s)', (LOCK_ID,))
        conn.close()


if __name__ == '__main__':
    main()
