"""AUTH-02 防回歸（PLAN AUTH-02 (e)，Q3 裁示：ALLOW_REGISTER 預設 false＋邀請制）。
預設關閉自助註冊；需 [AuthView] ALLOW_REGISTER=true 明示開啟。"""
import os
import tempfile
from pathlib import Path

import pytest
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(element, compiler, **kw):  # pragma: no cover
    return "JSON"


os.environ.setdefault("QT_API", "None")
os.environ.setdefault("MPLBACKEND", "Agg")

pytestmark = pytest.mark.integration

CFG_TEMPLATE = """
[FunlabFlask]
APP_NAME='{name}'
SECRET_KEY='reg-secret'
PREWARM_ENABLED=false
HOME_ENTRY='blank.html'
ENV = '{{{{ENV.T}}}}'
[ENV]
  [ENV.T]
  TESTING = true
  WSGI = 'flask'
  PORT = {port}
  DATABASE = '{{{{DATABASE.T}}}}'
[DATABASE]
  [DATABASE.T]
  url = 'sqlite:///{dbpath}'
[CACHE]
CACHE_TYPE='SimpleCache'
[AuthView]
{auth_extra}
"""


def _make_app(name, port, auth_extra=""):
    from funlab.flaskr.app import FunlabFlask
    dbpath = tempfile.mktemp(suffix=".db", dir=os.environ.get("TMPDIR"))
    cfgfile = tempfile.mktemp(suffix=".toml", dir=os.environ.get("TMPDIR"))
    Path(cfgfile).write_text(CFG_TEMPLATE.format(name=name, port=port,
                                                 dbpath=dbpath, auth_extra=auth_extra))
    app = FunlabFlask(configfile=cfgfile, envfile=None,
                      import_name=name, template_folder="", static_folder="")
    assert "auth" in app.plugins and str(app.security_mode).endswith("SECURED")
    app.config["WTF_CSRF_ENABLED"] = False
    return app


@pytest.fixture(scope="module")
def auth_app():
    app = _make_app('authreg02', 6002)
    yield app
    app.dbmgr.release()


@pytest.fixture(scope="module")
def auth_app_openreg():
    app = _make_app('authregopen02', 6003, auth_extra="ALLOW_REGISTER = true\n")
    yield app
    app.dbmgr.release()


def test_register_closed_by_default(auth_app):
    c = auth_app.test_client()
    r = c.post('/register', data={'register': '1', 'username': 'm',
                                  'email': 'm@x.io', 'password': '***'})
    assert r.status_code == 302                      # 導向登入
    assert b"Registration is disabled" in c.get('/login/').data


def test_register_get_also_redirects_when_closed(auth_app):
    """紅線（PLAN (g)）：關閉狀態下 GET /register 表單也不保留。"""
    c = auth_app.test_client()
    assert c.get('/register').status_code == 302


def test_register_placeholder_password_rejected(auth_app_openreg):
    from funlab.auth.user import EXTERNAL_AUTH_PLACEHOLDER
    c = auth_app_openreg.test_client()
    r = c.post('/register', data={'register': '1', 'username': 't',
                                  'email': 't2@x.io',
                                  'password': EXTERNAL_AUTH_PLACEHOLDER})
    assert b"Invalid password" in r.data or _has_flash(c, "Invalid password")


def test_register_open_allows_and_validates(auth_app_openreg):
    c = auth_app_openreg.test_client()
    r = c.post('/register', data={'register': '1', 'username': 'ok',
                                  'email': 'ok@x.io', 'password': '***'})
    assert b"Account is created successfully" in r.data or _has_flash(c, "created successfully")
    # 表單驗證生效：壞 email 不再 400/KeyError，而是 200 + Invalid flash
    r2 = c.post('/register', data={'register': '1', 'username': 'bad',
                                   'email': 'not-an-email', 'password': '***'})
    assert r2.status_code == 200


def test_register_get_form_available_when_open(auth_app_openreg):
    """ALLOW_REGISTER=true 時 GET /register 表單可用（PLAN (g) 只禁關閉態保留表單）。"""
    c = auth_app_openreg.test_client()
    r = c.get('/register')
    assert r.status_code == 200


def _has_flash(client, needle):
    with client.session_transaction() as sess:
        msgs = [m for _, m in sess.get("_flashes", [])]
        sess.pop("_flashes", None)
        return any(needle in m for m in msgs)
