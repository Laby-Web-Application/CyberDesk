"""CyberDesk: Flask/PostgreSQL web application, with explicit SQLite preview/test mode.

Used by: ALL environments (AWS Cloud via Gunicorn, Legacy Self-Hosted via Docker
Compose, Local Dev via preview_server.py, and CI/CD via pytest).

Architecture inside this file (Part 1):
  1. Database Layer   : Thin wrapper (`Database`) + connection context manager (`database()`).
  2. Schema & Seeding : `init_db()` (reads init.sql) and `seed_demo()` (demo accounts/data).
  3. Security Helpers : CSRF tokens, RBAC decorators, IDOR protection (`visible_report`), audit log.
  4. App Factory      : `create_app()` configures Flask, AWS ProxyFix, global before/after
                        security hooks, Jinja2 template filters, and the `/health` check.
"""
import functools
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from pathlib import Path
import click
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, abort, current_app, flash, g, redirect, render_template, request, session, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

# Project root directory (`/app` in Docker) used to locate `init.sql` and `instance/`.
ROOT = Path(__file__).resolve().parent

# Strict server-side allowlists for report severity and workflow status.
# Used both for validating incoming form data and rendering dropdowns in templates.
SEVERITIES = ('Niska', 'Średnia', 'Wysoka', 'Krytyczna')
STATUSES = ('Nowe', 'W trakcie analizy', 'Naprawione')


# ==============================================================================
# 1. DATABASE ABSTRACTION LAYER
# ==============================================================================

class Database:
    """Thin wrapper around a raw DB-API connection (psycopg2 or sqlite3).

    Why it exists:
      Production (AWS RDS & Docker Compose) uses PostgreSQL (`%s` placeholders),
      while `pytest` and `preview_server.py` use SQLite (`?` placeholders).
      This class hides that difference so routes only write one SQL dialect.
    """

    def __init__(self, conn, local=False):
        self.conn, self.local = conn, local

    def execute(self, sql, params=()):
        cur = self.conn.cursor()
        # SQL Injection Defense: `sql` is always developer-authored; user input
        # is passed separately in `params` as bound parameters so the database
        # never interprets user text as executable SQL.
        cur.execute(sql.replace('%s', '?') if self.local else sql, params)
        return cur

    def one(self, sql, params=()):
        """Execute a query and return the first row as a Python dict (or None)."""
        row = self.execute(sql, params).fetchone()
        return dict(row) if row is not None else None

    def all(self, sql, params=()):
        """Execute a query and return all matching rows as a list of dicts."""
        return [dict(row) for row in self.execute(sql, params).fetchall()]


@contextmanager
def database():
    """Context manager (`with database() as db:`) managing connection lifecycle.

    Guarantees:
      - Automatically opens either SQLite (tests/preview) or PostgreSQL (prod).
      - Commits the transaction if the `with` block finishes without error.
      - Rolls back the transaction if any Python exception is raised.
      - Always closes the underlying socket/file handle in `finally`.
    """
    local = current_app.config['DB_ENGINE'] == 'sqlite'
    if local:
        # Local Dev / CI Tests (SQLite)
        conn = sqlite3.connect(current_app.config['SQLITE_PATH'], timeout=15)
        conn.row_factory = sqlite3.Row  # Allows accessing columns by name (row['id'])
        # SQLite disables foreign keys by default; turn them ON so ON DELETE CASCADE works.
        conn.execute('PRAGMA foreign_keys = ON')
    else:
        # Production (AWS RDS & Legacy Docker Compose PostgreSQL)
        # - RealDictCursor returns rows as dicts matching sqlite3.Row behavior.
        # - timezone=UTC ensures timestamps are stored consistently regardless of server locale.
        options = dict(cursor_factory=RealDictCursor, connect_timeout=10, options='-c timezone=UTC')
        if current_app.config['DATABASE_URL']:
            conn = psycopg2.connect(current_app.config['DATABASE_URL'], **options)
        else:
            conn = psycopg2.connect(
                host=os.environ.get('DB_HOST', 'localhost'),
                database=os.environ.get('DB_NAME', 'vulntrack'),
                user=os.environ.get('DB_USER', 'postgres'),
                password=os.environ.get('DB_PASS', ''),
                **options,
            )
    try:
        yield Database(conn, local)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ==============================================================================
# 2. SCHEMA INITIALIZATION & DEMO SEEDING
# ==============================================================================

def init_db():
    """Idempotently create or upgrade all database tables from `init.sql`.

    Called by `scripts/bootstrap_db.py` at container boot (as schema owner),
    by `preview_server.py`, and by `pytest` fixtures.
    """
    with database() as db:
        if not db.local:
            # LEGACY MIGRATION PATH: Safely upgrades databases created by an older
            # version of the project without dropping existing user/report data.
            db.execute("CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, password TEXT NOT NULL, role VARCHAR(20) NOT NULL DEFAULT 'user')")
            db.execute('ALTER TABLE users ALTER COLUMN password TYPE TEXT')
            db.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
            db.execute("CREATE TABLE IF NOT EXISTS reports (id SERIAL PRIMARY KEY, author VARCHAR(50) NOT NULL, title VARCHAR(150) NOT NULL, description TEXT NOT NULL, severity VARCHAR(20) NOT NULL, approved BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
            db.execute("ALTER TABLE reports ADD COLUMN IF NOT EXISTS status VARCHAR(30) NOT NULL DEFAULT 'Nowe'")
            db.execute('ALTER TABLE reports ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')

        # Load the canonical schema from init.sql.
        schema = (ROOT / 'init.sql').read_text()
        if db.local:
            # Translate PostgreSQL auto-increment syntax to SQLite syntax.
            schema = schema.replace('SERIAL PRIMARY KEY', 'INTEGER PRIMARY KEY AUTOINCREMENT')
        for statement in schema.split(';'):
            if statement.strip():
                db.execute(statement)

        # LEGACY PASSWORD MIGRATION: If any old database row still has a plaintext
        # password (missing Werkzeug's `scrypt:` or `pbkdf2:` prefix), hash it in place.
        for user in db.all('SELECT id, password FROM users'):
            if not user['password'].startswith(('scrypt:', 'pbkdf2:')):
                db.execute('UPDATE users SET password=%s WHERE id=%s', (generate_password_hash(user['password']), user['id']))


def seed_demo():
    """Populate demo accounts (`admin`, `user`) and 4 sample reports if the DB is empty.

    Only runs when `DEMO_MODE=1`. Safe to call repeatedly (`ON CONFLICT DO NOTHING`
    and early return if reports already exist).
    """
    with database() as db:
        for name, password, role in [('admin', 'CyberDeskAdmin!2026', 'admin'), ('user', 'CyberDeskUser!2026', 'user')]:
            db.execute('INSERT INTO users (username,password,role) VALUES (%s,%s,%s) ON CONFLICT (username) DO NOTHING', (name, generate_password_hash(password), role))
        if db.one('SELECT COUNT(*) AS n FROM reports')['n']:
            return
        examples = [
            ('admin', 'Nieprawidłowa kontrola dostępu do faktur', 'Zmiana identyfikatora faktury w adresie pozwala odczytać dokument innego użytkownika.\n\nKroki odtworzenia:\n1. Zaloguj się na konto testowe.\n2. Otwórz własną fakturę.\n3. Zmień identyfikator na dokument drugiego konta testowego.\n\nOczekiwane zachowanie: odpowiedź 403 lub 404. Test wykonano w środowisku laboratoryjnym.', 'Krytyczna', 'W trakcie analizy', True),
            ('user', 'Brak ograniczenia prób logowania w panelu testowym', 'Panel testowanej aplikacji pozwala wielokrotnie wysyłać błędne hasło bez czasowej blokady. Należy wprowadzić limit prób i rejestrowanie nieudanych logowań.', 'Wysoka', 'Nowe', True),
            ('admin', 'Brak nagłówka X-Content-Type-Options', 'Odpowiedzi serwera nie zawierały nagłówka nosniff. Dodano go w konfiguracji serwera i potwierdzono jego obecność w odpowiedziach.', 'Niska', 'Naprawione', True),
            ('user', 'Zbyt szczegółowy komunikat błędu API', 'Niepoprawny parametr powoduje wyświetlenie wewnętrznej ścieżki pliku. Zamiast szczegółów implementacji użytkownik powinien otrzymywać ogólny komunikat błędu.', 'Średnia', 'Nowe', False),
        ]
        for author, title, description, severity, status, approved in examples:
            db.execute('INSERT INTO reports (author,title,description,severity,status,approved) VALUES (%s,%s,%s,%s,%s,%s)', (author, title, description, severity, status, approved))
        rid = db.one('SELECT id FROM reports ORDER BY id LIMIT 1')['id']
        db.execute('INSERT INTO comments (report_id,author,content) VALUES (%s,%s,%s)', (rid, 'user', 'Potwierdzam w środowisku testowym. Problem dotyczy również eksportu dokumentu do PDF.'))


# ==============================================================================
# 3. SECURITY, AUTHORIZATION & VALIDATION HELPERS
# ==============================================================================

def csrf_token():
    """Return the current session's anti-CSRF token, generating one if absent.

    Stored inside Flask's cryptographically signed session cookie and embedded
    into every HTML <form> via the `{{ csrf() }}` macro in templates/base.html.
    """
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_urlsafe(32)
    return session['_csrf']


def login_required(view):
    """Route decorator: redirects unauthenticated visitors to `/login`."""
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash('Zaloguj się, aby wykonać tę czynność.', 'warning')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped


def is_admin():
    """Check whether the currently loaded live DB user has the `admin` role."""
    return bool(g.user and g.user['role'] == 'admin')


def admin_required(view):
    """Route decorator: requires login AND `admin` role, otherwise returns HTTP 403."""
    @login_required
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not is_admin():
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def visible_report(db, rid):
    """IDOR Protection: fetch a report ONLY if the current user is allowed to see it.

    A report is visible if:
      - It is publicly approved (`approved == True`), OR
      - The current user is an admin, OR
      - The current user is the report's author.
    Returns HTTP 404 (not 403) when hidden so attackers cannot probe whether a
    private report ID exists.
    """
    report = db.one('SELECT * FROM reports WHERE id=%s', (rid,))
    if not report or not (report['approved'] or is_admin() or (g.user and report['author'] == g.user['username'])):
        abort(404)
    return report


def audit(db, event, rid=None, detail=''):
    """Record an immutable audit trail entry for administrative visibility."""
    db.execute('INSERT INTO audit_events (actor,event,report_id,detail) VALUES (%s,%s,%s,%s)', (g.user['username'], event, rid, detail))


def report_values():
    """Validate and extract report form inputs server-side (never trust HTML `required`)."""
    title, description = request.form.get('title', '').strip(), request.form.get('description', '').strip()
    severity = request.form.get('severity', '')
    if not 3 <= len(title) <= 150:
        return None, 'Tytuł musi mieć od 3 do 150 znaków.'
    if not 10 <= len(description) <= 10000:
        return None, 'Opis musi mieć od 10 do 10 000 znaków.'
    if severity not in SEVERITIES:
        return None, 'Wybierz prawidłowy poziom zagrożenia.'
    return (title, description, severity), None


# ==============================================================================
# 4. FLASK APPLICATION FACTORY, MIDDLEWARE & HEALTH CHECK
# ==============================================================================

def create_app(test_config=None):
    """Build and configure the Flask application instance.

    Using the Application Factory pattern lets `pytest` create isolated app
    instances with custom SQLite configs without polluting global state.
    """
    app = Flask(__name__)
    app.config.update(
        # Shared cryptographic key for signing session cookies across all EC2 nodes.
        SECRET_KEY=os.environ.get('SECRET_KEY'),
        DB_ENGINE=os.environ.get('APP_DB', 'postgres'),
        SQLITE_PATH=os.environ.get('SQLITE_PATH', str(ROOT / 'instance' / 'preview.db')),
        DATABASE_URL=os.environ.get('DATABASE_URL'),
        DEMO_MODE=os.environ.get('DEMO_MODE') == '1',
        # Cookie Hardening:
        # - HttpOnly: Blocks JavaScript (`document.cookie`) from reading the session (XSS defense).
        # - SameSite=Lax: Stops cross-site POSTs from attaching the cookie (CSRF defense).
        # - Secure: Only sends cookies over HTTPS (enabled in AWS via COOKIE_SECURE=1).
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE') == '1',
        PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
        # Reject any HTTP request body larger than 64 KB (HTTP 413) to prevent DoS.
        MAX_CONTENT_LENGTH=65536,
    )
    if test_config:
        app.config.update(test_config)

    # CLOUD (AWS ALB) MIDDLEWARE:
    # Behind exactly 1 trusted reverse proxy (AWS ALB), restore the real client IP
    # (`X-Forwarded-For`) and original HTTPS scheme (`X-Forwarded-Proto`).
    # Without this, every user shares the ALB's private IP (breaking per-client
    # login rate limiting) and `request.is_secure` is False (disabling HSTS).
    # Never enable without a proxy in front, or clients could spoof X-Forwarded-For.
    if os.environ.get('TRUST_PROXY') == '1':
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    # LOCAL DEV FALLBACK:
    # If SECRET_KEY wasn't provided via env (e.g., running preview_server.py),
    # atomically generate and persist a random key in `instance/.session-key`.
    # (In AWS Cloud, SECRET_KEY always comes from AWS Secrets Manager.)
    if not app.config['SECRET_KEY']:
        instance = ROOT / 'instance'
        instance.mkdir(exist_ok=True, mode=0o700)
        keyfile = instance / '.session-key'
        try:
            with keyfile.open('x') as handle:
                os.chmod(keyfile, 0o600)
                handle.write(secrets.token_hex(32))
        except FileExistsError:
            pass
        app.config['SECRET_KEY'] = keyfile.read_text().strip()

    # --------------------------------------------------------------------------
    # GLOBAL PRE-REQUEST SECURITY GATEKEEPER
    # --------------------------------------------------------------------------
    @app.before_request
    def protect_request():
        """Runs automatically before EVERY route handler."""
        g.user = None
        # Static assets and ALB/Docker health checks don't need sessions or CSRF.
        if request.endpoint in ('static', 'health'):
            return

        # 1. Global CSRF Enforcement: Every state-changing POST request must
        #    present a form `csrf_token` matching the session's `_csrf` secret.
        #    `hmac.compare_digest` prevents timing side-channel attacks.
        if request.method == 'POST':
            token, expected = request.form.get('csrf_token', ''), session.get('_csrf', '')
            if not expected or not hmac.compare_digest(expected.encode(), token.encode()):
                abort(400, description='Formularz wygasł lub brakuje tokenu CSRF. Odśwież stronę i spróbuj ponownie.')

        # 2. Live Identity & Role Lookup: Never trust a `role` stored in a cookie.
        #    Fetch the user's current role from PostgreSQL on every request so
        #    revoking admin rights or deleting a user takes effect immediately.
        if session.get('user_id'):
            with database() as db:
                g.user = db.one('SELECT id,username,role FROM users WHERE id=%s', (session['user_id'],))
            if not g.user:
                session.clear()

    # --------------------------------------------------------------------------
    # GLOBAL POST-REQUEST SECURITY HEADERS
    # --------------------------------------------------------------------------
    @app.after_request
    def security_headers(response):
        """Stamp defense-in-depth HTTP security headers onto every outgoing response."""
        response.headers.update({
            'X-Content-Type-Options': 'nosniff',     # Prevent MIME-type sniffing
            'X-Frame-Options': 'SAMEORIGIN',         # Prevent Clickjacking
            'Referrer-Policy': 'same-origin',        # Don't leak internal URLs externally
            # Strict Content Security Policy: blocks inline <script> and external CDNs
            'Content-Security-Policy': "default-src 'self'; style-src 'self'; img-src 'self' data:; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'",
        })
        # Prevent browsers/proxies from caching sensitive authenticated HTML pages.
        if request.endpoint != 'static':
            response.headers['Cache-Control'] = 'no-store'
        # Tell browsers to enforce HTTPS for 1 year (only sent when behind HTTPS/ALB).
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

    # --------------------------------------------------------------------------
    # JINJA2 TEMPLATE CONTEXT & FILTERS
    # --------------------------------------------------------------------------
    @app.context_processor
    def context():
        """Inject common helpers/constants into every Jinja2 template automatically."""
        return dict(csrf_token=csrf_token, severities=SEVERITIES, statuses=STATUSES, admin=is_admin(), demo=app.config['DEMO_MODE'])

    @app.template_filter('shortdate')
    def shortdate(value):
        """Convert UTC database timestamps into Polish local time (`Europe/Warsaw`)."""
        if not value:
            return '—'
        moment = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(ZoneInfo('Europe/Warsaw')).strftime('%Y-%m-%d %H:%M')

    # Map Polish severity/status labels to CSS class suffixes (e.g. 'Krytyczna' -> 'critical').
    app.add_template_filter(lambda value: dict(zip(SEVERITIES, ('low', 'medium', 'high', 'critical'))).get(value, 'low'), 'severity_class')
    app.add_template_filter(lambda value: dict(zip(STATUSES, ('new', 'analysis', 'fixed'))).get(value, 'new'), 'status_class')

    # --------------------------------------------------------------------------
    # HEALTH CHECK ENDPOINT (AWS ALB + Docker Compose + CI/CD Smoke Test)
    # --------------------------------------------------------------------------
    @app.get('/health')
    def health():
        """Lightweight liveness + DB connectivity check.

        Polled every 15s by AWS ALB TargetGroup, every 10s by docker-compose.yml,
        and by `cyberdesk-deploy.sh` / GitHub Actions after every rollout.
        Returns 200 OK only if PostgreSQL responds to `SELECT 1`; otherwise 503.
        """
        try:
            with database() as db:
                db.one('SELECT 1 AS ok')
            return {'status': 'ok'}
        except (psycopg2.Error, sqlite3.Error):
            return {'status': 'unavailable'}, 503

    # ==========================================================================
    # 5. REPORT LISTING, FILTERING & PAGINATION ENGINE
    # ==========================================================================

    def listing(scope):
        """Shared query builder for `/`, `/my-reports`, and `/admin`.

        Instead of duplicating SQL and pagination logic across three routes,
        this helper scopes the query dynamically:
          - 'all'   : Only publicly approved reports (`r.approved = TRUE`).
          - 'mine'  : All reports authored by the logged-in user (including pending).
          - 'admin' : Filtered by `?moderation=pending|approved|all`.
        """
        conditions, params = [], []
        if scope == 'mine':
            conditions.append('r.author=%s')
            params.append(g.user['username'])
        elif scope == 'admin':
            moderation = request.args.get('moderation', 'pending')
            if moderation in ('pending', 'approved'):
                conditions.append('r.approved=%s')
                params.append(moderation == 'approved')
        else:
            conditions.append('r.approved=TRUE')

        # Free-text search across title and description (capped at 150 chars).
        # `%` wildcards are wrapped around the bound parameter, never concatenated into SQL.
        q = request.args.get('q', '').strip()[:150]
        if q:
            conditions.append('(LOWER(r.title) LIKE LOWER(%s) OR LOWER(r.description) LIKE LOWER(%s))')
            params.extend([f'%{q}%', f'%{q}%'])

        # Strict allowlist filtering for severity and status.
        # Because `name` comes from the hardcoded tuple below and `value` is checked
        # against SEVERITIES/STATUSES, no user input can ever alter the SQL structure.
        for name, choices in [('severity', SEVERITIES), ('status', STATUSES)]:
            value = request.args.get(name, '')
            if value in choices:
                conditions.append('r.' + name + '=%s')
                params.append(value)

        where = ' AND '.join(conditions) or '1=1'
        # `type=int` safely falls back to 1 if someone visits `/?page=abc`.
        page = max(1, request.args.get('page', 1, type=int))

        with database() as db:
            # Bandit SAST (B608) flags string concatenation in SQL queries.
            # nosec justification: `where` joins only hard-coded fragments (column names
            # from fixed tuples); every user-supplied value is passed separately in `params`.
            total = db.one('SELECT COUNT(*) AS n FROM reports r WHERE ' + where, params)['n']  # nosec B608
            pages = max(1, (total + 9) // 10)  # Ceiling division for 10 reports per page
            page = min(page, pages)            # Clamp out-of-range page numbers
            reports = db.all(
                'SELECT r.*, (SELECT COUNT(*) FROM comments c WHERE c.report_id=r.id) AS comment_count '
                'FROM reports r WHERE ' + where + ' ORDER BY r.created_at DESC,r.id DESC LIMIT %s OFFSET %s',
                params + [10, (page - 1) * 10],
            )  # nosec B608

            # Top dashboard KPI cards (always computed over publicly approved reports).
            stats = db.one(
                "SELECT COUNT(*) AS total, "
                "COALESCE(SUM(CASE WHEN status <> 'Naprawione' THEN 1 ELSE 0 END),0) AS active, "
                "COALESCE(SUM(CASE WHEN status = 'Naprawione' THEN 1 ELSE 0 END),0) AS fixed, "
                "COALESCE(SUM(CASE WHEN severity = 'Krytyczna' AND status <> 'Naprawione' THEN 1 ELSE 0 END),0) AS critical "
                "FROM reports WHERE approved=TRUE"
            )
            # Pending badge counter shown in the sidebar for admins only.
            pending = db.one('SELECT COUNT(*) AS n FROM reports WHERE approved=FALSE')['n'] if is_admin() else None

        def page_url(n):
            """Preserve active search/filter query params when clicking Next/Prev."""
            args = request.args.to_dict()
            args['page'] = n
            return url_for(request.endpoint, **args)

        return render_template('index.html', scope=scope, reports=reports, stats=stats, pending=pending, total=total, page=page, pages=pages, page_url=page_url)

    @app.get('/')
    def index():
        return listing('all')

    @app.get('/my-reports')
    @login_required
    def my_reports():
        return listing('mine')

    @app.get('/admin')
    @admin_required
    def admin_panel():
        return listing('admin')

    @app.get('/admin/audit')
    @admin_required
    def audit_log():
        """Display the 100 most recent security/moderation events."""
        with database() as db:
            events = db.all('SELECT * FROM audit_events ORDER BY id DESC LIMIT 100')
        return render_template('audit.html', events=events)

    # ==========================================================================
    # 6. AUTHENTICATION (REGISTER, LOGIN WITH RATE LIMITING, LOGOUT)
    # ==========================================================================

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if g.user:
            return redirect(url_for('index'))
        if request.method == 'POST':
            username = request.form.get('username', '').strip().lower()
            password = request.form.get('password', '')
            error = None
            if not re.fullmatch(r'[a-z0-9_.-]{3,50}', username):
                error = 'Login: 3–50 znaków, litery bez polskich znaków, cyfry, kropka, myślnik lub podkreślenie.'
            elif not 10 <= len(password) <= 128:
                error = 'Hasło musi mieć od 10 do 128 znaków.'
            elif password != request.form.get('confirm_password', ''):
                error = 'Podane hasła nie są identyczne.'
            if not error:
                with database() as db:
                    # Mass-Assignment Defense: role is hardcoded to 'user' in SQL,
                    # ignoring any `role=admin` field an attacker might inject in POST data.
                    # ON CONFLICT DO NOTHING works with `users_username_lower` to block
                    # case-insensitive duplicates cleanly without leaking DB exceptions.
                    cur = db.execute(
                        "INSERT INTO users (username,password,role) VALUES (%s,%s,'user') ON CONFLICT DO NOTHING",
                        (username, generate_password_hash(password)),
                    )
                    if not cur.rowcount:
                        error = 'Ten login jest już zajęty.'
                if not error:
                    flash('Konto zostało utworzone. Możesz się zalogować.', 'success')
                    return redirect(url_for('login'))
            flash(error, 'danger')
            return render_template('auth.html', mode='register'), 400
        return render_template('auth.html', mode='register')

    # Timing-Attack Defense: Pre-computed hash used when a login username doesn't
    # exist so `check_password_hash` still takes the same CPU time, preventing
    # attackers from enumerating valid usernames by measuring response latency.
    dummy_hash = generate_password_hash(secrets.token_urlsafe(20))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if g.user:
            return redirect(url_for('index'))
        if request.method == 'POST':
            username = request.form.get('username', '').strip().lower()[:50]
            password = request.form.get('password', '')
            now = int(time.time())
            # Behind AWS ALB, ProxyFix populates `request.remote_addr` with the real client IP.
            ip = request.remote_addr or 'unknown'

            # Dual-Bucket Brute-Force Protection (stored in PostgreSQL so all EC2 nodes share state):
            #   1. Per-account+IP bucket : 5 failed attempts -> 15-minute lockout.
            #   2. Per-IP bucket         : 30 failed attempts across any accounts -> 15-minute lockout.
            buckets = [
                (hashlib.sha256(f'account:{ip}:{username}'.encode()).hexdigest(), 5),
                (hashlib.sha256(f'ip:{ip}'.encode()).hexdigest(), 30),
            ]
            with database() as db:
                # Probabilistic Pruning: On ~5% of login attempts, purge expired rows
                # using the `login_attempts_last_attempt` index so bot sprays don't
                # bloat the table indefinitely. Uses `secrets` so Bandit SAST stays happy.
                if secrets.randbelow(20) == 0:
                    db.execute('DELETE FROM login_attempts WHERE last_attempt < %s AND blocked_until < %s', (now - 900, now))

                # Check if either bucket is currently locked out (HTTP 429).
                for key, limit in buckets:
                    attempt = db.one('SELECT * FROM login_attempts WHERE key=%s', (key,))
                    if attempt and attempt['blocked_until'] > now:
                        flash('Za dużo nieudanych prób. Spróbuj ponownie za 15 minut.', 'danger')
                        response = app.make_response((render_template('auth.html', mode='login'), 429))
                        response.headers['Retry-After'] = str(attempt['blocked_until'] - now)
                        return response

                user = db.one('SELECT * FROM users WHERE LOWER(username)=%s', (username,))
                # Cap password length at 128 chars before hashing to prevent CPU DoS.
                valid = len(password) <= 128 and check_password_hash(user['password'] if user else dummy_hash, password)
                if not user or not valid:
                    for key, limit in buckets:
                        # Increment counter (or reset to 1 if the previous attempt was >15 min ago).
                        db.execute(
                            'INSERT INTO login_attempts (key,attempts,last_attempt,blocked_until) VALUES (%s,1,%s,0) '
                            'ON CONFLICT (key) DO UPDATE SET '
                            'attempts=CASE WHEN login_attempts.last_attempt < %s THEN 1 ELSE login_attempts.attempts+1 END, '
                            'last_attempt=%s',
                            (key, now, now - 900, now),
                        )
                        db.execute('UPDATE login_attempts SET blocked_until=%s WHERE key=%s AND attempts >= %s', (now + 900, key, limit))
                    flash('Błędny login lub hasło.', 'danger')
                    return render_template('auth.html', mode='login'), 401

                # Successful login: clear the per-account+IP failure counter.
                db.execute('DELETE FROM login_attempts WHERE key=%s', (buckets[0][0],))

            # Session Fixation Defense: wipe the pre-login session and rotate the
            # CSRF token so any pre-authentication token becomes invalid.
            session.clear()
            session['user_id'] = user['id']
            session.permanent = True
            csrf_token()
            flash('Zalogowano pomyślnie.', 'success')
            return redirect(url_for('index'))
        return render_template('auth.html', mode='login')

    @app.post('/logout')
    def logout():
        """POST-only logout (prevents CSRF logout attacks via <img src='/logout'>)."""
        session.clear()
        flash('Wylogowano.', 'info')
        return redirect(url_for('index'))

    # ==========================================================================
    # 7. REPORT CRUD & ADMIN MODERATION
    # ==========================================================================

    @app.route('/add_report', methods=['GET', 'POST'])
    @login_required
    def add_report():
        if request.method == 'POST':
            values, error = report_values()
            if error:
                flash(error, 'danger')
                return render_template('add_report.html', report=None), 400
            with database() as db:
                # Admin reports are auto-approved; regular user reports start hidden (`approved=False`).
                report = db.one(
                    'INSERT INTO reports (author,title,description,severity,approved) VALUES (%s,%s,%s,%s,%s) RETURNING id',
                    (g.user['username'], *values, is_admin()),
                )
                audit(db, 'Dodano zgłoszenie', report['id'])
            flash('Zgłoszenie opublikowano.' if is_admin() else 'Zgłoszenie zapisano. Czeka na akceptację administratora.', 'success')
            return redirect(url_for('report_detail', report_id=report['id']))
        return render_template('add_report.html', report=None)

    @app.get('/reports/<int:report_id>')
    def report_detail(report_id):
        with database() as db:
            report = visible_report(db, report_id)
            comments = db.all('SELECT * FROM comments WHERE report_id=%s ORDER BY created_at,id', (report_id,))
        can_edit = bool(g.user and (is_admin() or g.user['username'] == report['author']))
        return render_template('report.html', report=report, comments=comments, can_edit=can_edit)

    @app.route('/reports/<int:report_id>/edit', methods=['GET', 'POST'])
    @login_required
    def edit_report(report_id):
        with database() as db:
            report = visible_report(db, report_id)
            # Ownership check: only admins or the original author may edit.
            if not is_admin() and report['author'] != g.user['username']:
                abort(403)
            if request.method == 'POST':
                values, error = report_values()
                if error:
                    flash(error, 'danger')
                    return render_template('add_report.html', report=report), 400
                # Moderation Integrity: if a regular user edits an already-approved
                # report, reset `approved=False` and `status='Nowe'` so an admin
                # must re-verify the new content before it becomes public again.
                approved = bool(report['approved']) if is_admin() else False
                status = report['status'] if is_admin() else 'Nowe'
                db.execute(
                    'UPDATE reports SET title=%s,description=%s,severity=%s,approved=%s,status=%s,updated_at=CURRENT_TIMESTAMP WHERE id=%s',
                    (*values, approved, status, report_id),
                )
                audit(db, 'Edytowano zgłoszenie', report_id)
                flash('Zmiany zapisano.' if is_admin() else 'Zmiany zapisano. Zgłoszenie ponownie czeka na akceptację.', 'success')
                return redirect(url_for('report_detail', report_id=report_id))
        return render_template('add_report.html', report=report)

    @app.post('/approve/<int:report_id>')
    @admin_required
    def approve_report(report_id):
        with database() as db:
            visible_report(db, report_id)
            db.execute('UPDATE reports SET approved=TRUE,updated_at=CURRENT_TIMESTAMP WHERE id=%s', (report_id,))
            audit(db, 'Zaakceptowano zgłoszenie', report_id)
        flash('Zgłoszenie zaakceptowano i opublikowano.', 'success')
        return redirect(url_for('report_detail', report_id=report_id))

    @app.post('/reports/<int:report_id>/status')
    @admin_required
    def change_status(report_id):
        status = request.form.get('status', '')
        if status not in STATUSES:
            abort(400, description='Nieprawidłowy status.')
        with database() as db:
            report = visible_report(db, report_id)
            db.execute('UPDATE reports SET status=%s,updated_at=CURRENT_TIMESTAMP WHERE id=%s', (status, report_id))
            audit(db, 'Zmieniono status', report_id, f"{report['status']} → {status}")
        flash('Status zaktualizowano.', 'success')
        return redirect(url_for('report_detail', report_id=report_id))

    @app.post('/delete/<int:report_id>')
    @admin_required
    def delete_report(report_id):
        """Delete a report (database ON DELETE CASCADE removes its comments too)."""
        with database() as db:
            report = visible_report(db, report_id)
            # Log audit event BEFORE deleting so the report title is preserved.
            audit(db, 'Usunięto zgłoszenie', report_id, report['title'])
            db.execute('DELETE FROM reports WHERE id=%s', (report_id,))
        flash('Zgłoszenie usunięto wraz z komentarzami.', 'info')
        return redirect(url_for('admin_panel'))

    # ==========================================================================
    # 8. COMMENTS
    # ==========================================================================

    @app.post('/comment/<int:report_id>')
    @login_required
    def add_comment(report_id):
        content = request.form.get('content', '').strip()
        with database() as db:
            report = visible_report(db, report_id)
            if not report['approved']:
                abort(403, description='Komentowanie jest dostępne po akceptacji zgłoszenia.')
            if not 1 <= len(content) <= 2000:
                abort(400, description='Komentarz musi mieć od 1 do 2000 znaków.')
            db.execute('INSERT INTO comments (report_id,author,content) VALUES (%s,%s,%s)', (report_id, g.user['username'], content))
            audit(db, 'Dodano komentarz', report_id)
        flash('Komentarz dodano.', 'success')
        return redirect(url_for('report_detail', report_id=report_id) + '#comments')

    @app.post('/comments/<int:comment_id>/delete')
    @login_required
    def delete_comment(comment_id):
        with database() as db:
            comment = db.one('SELECT * FROM comments WHERE id=%s', (comment_id,))
            if not comment:
                abort(404)
            visible_report(db, comment['report_id'])
            if not is_admin() and comment['author'] != g.user['username']:
                abort(403)
            db.execute('DELETE FROM comments WHERE id=%s', (comment_id,))
            audit(db, 'Usunięto komentarz', comment['report_id'])
        flash('Komentarz usunięto.', 'info')
        return redirect(url_for('report_detail', report_id=comment['report_id']) + '#comments')

    # ==========================================================================
    # 9. CUSTOM ERROR HANDLERS & FLASK CLI COMMANDS
    # ==========================================================================

    @app.errorhandler(HTTPException)
    def http_error(error):
        """Render friendly Polish error pages instead of default Werkzeug HTML."""
        messages = {
            403: 'Nie masz uprawnień do tej operacji.',
            404: 'Nie znaleziono zgłoszenia lub strony.',
            405: 'Ta operacja wymaga formularza POST.',
            413: 'Przesłany formularz jest zbyt duży.',
        }
        return render_template('error.html', code=error.code, message=messages.get(error.code, error.description)), error.code

    @app.errorhandler(500)
    def internal_error(error):
        """Never leak Python stack traces or SQL errors to end users."""
        return render_template('error.html', code=500, message='Wystąpił błąd serwera. Spróbuj ponownie później.'), 500

    # Manual operational CLI commands (e.g. `flask create-admin jan` when DEMO_MODE=0).
    @app.cli.command('init-db')
    def init_command():
        init_db()
        click.echo('Schemat bazy i migracja gotowe.')

    @app.cli.command('seed-demo')
    def seed_command():
        seed_demo()
        click.echo('Dodano dane demonstracyjne. Dane logowania opisano w README.')

    @app.cli.command('create-admin')
    @click.argument('username')
    @click.password_option(confirmation_prompt=True)
    def admin_command(username, password):
        username = username.strip().lower()
        if not re.fullmatch(r'[a-z0-9_.-]{3,50}', username) or not 10 <= len(password) <= 128:
            raise click.ClickException('Nieprawidłowy login lub długość hasła (10–128 znaków).')
        with database() as db:
            cur = db.execute("INSERT INTO users (username,password,role) VALUES (%s,%s,'admin') ON CONFLICT DO NOTHING", (username, generate_password_hash(password)))
            if not cur.rowcount:
                raise click.ClickException('Login jest zajęty. Nie zmieniono istniejącego konta.')
        click.echo('Utworzono administratora.')

    return app


# ==============================================================================
# 10. WSGI ENTRY POINT
# ==============================================================================
# Gunicorn loads this `app` object (`gunicorn ... app:app` in Dockerfile).
app = create_app()

if __name__ == '__main__':
    # LOCAL DEV ONLY: binds to 127.0.0.1 by default (Bandit B104 safe) with debug=False.
    # Production always runs via Gunicorn inside the Docker container.
    app.run(host=os.environ.get('HOST', '127.0.0.1'), port=int(os.environ.get('PORT', 5000)), debug=False)
