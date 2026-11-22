"""Behaviour behind the AWS Application Load Balancer (TRUST_PROXY=1)."""
import os
import sys
from pathlib import Path

os.environ.setdefault('APP_DB', 'sqlite')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import create_app, init_db  # noqa: E402


def make_app(tmp_path, monkeypatch, trust_proxy):
    if trust_proxy:
        monkeypatch.setenv('TRUST_PROXY', '1')
    else:
        monkeypatch.delenv('TRUST_PROXY', raising=False)
    app = create_app({'TESTING': True, 'SECRET_KEY': 'test-secret-only', 'DB_ENGINE': 'sqlite',
                      'SQLITE_PATH': str(tmp_path / 'proxy.db')})
    with app.app_context():
        init_db()
    return app


def test_hsts_sent_when_alb_terminates_tls(tmp_path, monkeypatch):
    client = make_app(tmp_path, monkeypatch, True).test_client()
    response = client.get('/login', headers={'X-Forwarded-Proto': 'https'})
    assert response.headers.get('Strict-Transport-Security') == 'max-age=31536000'


def test_forwarded_headers_ignored_without_trusted_proxy(tmp_path, monkeypatch):
    client = make_app(tmp_path, monkeypatch, False).test_client()
    response = client.get('/login', headers={'X-Forwarded-Proto': 'https'})
    assert 'Strict-Transport-Security' not in response.headers


def test_login_lockout_is_per_client_behind_proxy(tmp_path, monkeypatch):
    app = make_app(tmp_path, monkeypatch, True)

    def failed_login(client, ip):
        headers = {'X-Forwarded-For': ip}
        client.get('/login', headers=headers)
        with client.session_transaction() as sess:
            token = sess['_csrf']
        return client.post('/login', headers=headers,
                           data={'csrf_token': token, 'username': 'nobody', 'password': 'wrong'}).status_code

    attacker = app.test_client()
    codes = [failed_login(attacker, '203.0.113.7') for _ in range(8)]
    assert 429 in codes, codes
    # A different client behind the same ALB must not inherit the attacker's lockout.
    assert failed_login(app.test_client(), '198.51.100.9') == 401
