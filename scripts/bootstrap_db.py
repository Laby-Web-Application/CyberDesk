"""Idempotent database bootstrap, run by entrypoint.sh as the schema owner before the app starts.

Used by: BOTH Legacy Self-Hosted (docker-compose.yml) AND Cloud (AWS EC2 / RDS)

Execution Flow:
  entrypoint.sh -> scripts/bootstrap_db.py -> app.init_db() (reads init.sql) -> ensures cyberdesk_app role

Why this script exists:
  Local Docker Postgres can run `db-init.sh` on first boot, but managed AWS RDS
  never runs local init scripts. Running this Python script before Gunicorn starts
  ensures the exact same database setup path works locally and in the cloud:
    1. Acquires a PostgreSQL advisory lock so multiple EC2 instances booting at
       once (e.g., an Auto Scaling Group) do not race each other.
    2. Creates/migrates tables (`app.init_db`) and optionally seeds demo data.
    3. Creates or updates the restricted runtime role (`cyberdesk_app`) with
       DML-only permissions (SELECT/INSERT/UPDATE/DELETE) — never DDL (DROP/ALTER).
"""
import os
import sys
from pathlib import Path

import psycopg2
from psycopg2 import sql

# ------------------------------------------------------------------------------
# MODULE PATH SETUP
# ------------------------------------------------------------------------------
# Because this script lives in `scripts/bootstrap_db.py`, Python's default import
# search path (`sys.path`) starts in `scripts/`, not the project root (`/app`).
# Inserting the parent directory (`parents[1]`) allows `from app import ...`
# to locate `/app/app.py` cleanly.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Arbitrary 64-bit integer used as a unique application-wide mutex key in PostgreSQL.
# Any two containers calling `pg_advisory_lock(74210001)` will coordinate on this
# exact lock so only one container runs migrations at a time.
LOCK_ID = 74210001


def connect():
    """Open a raw PostgreSQL connection using the schema owner credentials.

    entrypoint.sh passes DB_USER=cyberdesk and DB_PASS=$ADMIN_DB_PASS inline
    for this process only. `connect_timeout=10` prevents the container from
    hanging indefinitely if RDS or local Postgres is unreachable.
    """
    return psycopg2.connect(
        host=os.environ.get('DB_HOST', 'localhost'),
        dbname=os.environ.get('DB_NAME', 'vulntrack'),
        user=os.environ['DB_USER'],
        password=os.environ['DB_PASS'],
        connect_timeout=10,
    )


def ensure_app_role(cur, owner, app_user, app_password, dbname):
    """Idempotently create or update the restricted runtime DB role (`cyberdesk_app`).

    Idempotent means it can safely run 1 time or 100 times:
      - First boot: creates `cyberdesk_app` with `APP_DB_PASS`.
      - Subsequent boots / password rotations: updates `cyberdesk_app`'s password
        to match the current `APP_DB_PASS` (e.g., from AWS Secrets Manager).

    SQL Injection Safety:
      Standard `%s` placeholders only work for *values* (like passwords), NOT for
      SQL *identifiers* (like role or database names). `psycopg2.sql.Identifier()`
      safely quotes identifiers server-side, while `(app_password,)` remains a
      bound parameter.
    """
    # Check PostgreSQL's system catalog to see if the role already exists.
    cur.execute('SELECT 1 FROM pg_roles WHERE rolname=%s', (app_user,))
    verb = 'ALTER' if cur.fetchone() else 'CREATE'

    # Create the role (or sync its password if it already exists).
    # `WITH LOGIN` allows this role to authenticate; it has NO superuser or DDL rights.
    cur.execute(
        sql.SQL(verb + ' ROLE {} WITH LOGIN PASSWORD %s').format(sql.Identifier(app_user)),
        (app_password,),
    )

    role, owner_role = sql.Identifier(app_user), sql.Identifier(owner)

    # Apply least-privilege permissions:
    # 1. CONNECT: Allow logging into the `vulntrack` database.
    # 2. USAGE ON SCHEMA public: Allow looking up objects inside the `public` schema
    #    (does NOT grant CREATE, so `cyberdesk_app` cannot create new tables).
    # 3. SELECT/INSERT/UPDATE/DELETE ON ALL TABLES: Allow reading/writing app data
    #    on all existing tables (does NOT grant DROP, TRUNCATE, or ALTER).
    # 4. USAGE/SELECT ON ALL SEQUENCES: Required so `INSERT` into `SERIAL` primary
    #    key columns (like `reports.id`) can increment the auto-increment counter.
    # 5-6. ALTER DEFAULT PRIVILEGES: Automatically grant those exact same rights on
    #    any *future* tables/sequences created by `owner` (`cyberdesk`) in migrations.
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
    # Autocommit is required for DDL/role management statements and ensures the
    # session-level advisory lock isn't tied to a single rolled-back transaction.
    conn.autocommit = True

    try:
        # Context manager guarantees the cursor is closed even if an error occurs.
        with conn.cursor() as cur:
            # Block here until no other container holds LOCK_ID.
            # If 2 EC2 instances boot simultaneously in an Auto Scaling Group,
            # Instance A acquires the lock and runs migrations while Instance B waits.
            print('bootstrap: waiting for advisory lock', flush=True)
            cur.execute('SELECT pg_advisory_lock(%s)', (LOCK_ID,))
            try:
                # Late import: `app.py` calls `create_app()` at import time, which reads
                # environment variables (DB_USER, DB_PASS, SECRET_KEY, DEMO_MODE).
                # Importing inside the lock guarantees `init_db()` runs with the
                # schema owner credentials before Gunicorn starts.
                from app import app, init_db, seed_demo

                # Flask's `database()` helper relies on `current_app.config`, which is
                # only available inside an active Flask application context.
                with app.app_context():
                    init_db()
                    if os.environ.get('DEMO_MODE') == '1':
                        seed_demo()

                verb = ensure_app_role(cur, owner, app_user, app_password, dbname)
                state = 'created' if verb == 'CREATE' else 'updated'
                print(f'bootstrap: schema ready, role {app_user} {state}', flush=True)
            finally:
                # Always release the advisory lock once acquired so other booting
                # instances aren't left waiting.
                cur.execute('SELECT pg_advisory_unlock(%s)', (LOCK_ID,))
    finally:
        # Always close the underlying TCP socket to PostgreSQL.
        conn.close()


if __name__ == '__main__':
    main()












































































