"""AUTH-07 防回歸（PLAN AUTH-07 (e)）：logout GET 顯示確認頁、POST 才登出。

GET /logout 不再直接登出（防跨站 <img src=/logout> 強制登出）；
POST /logout 登出（CSRF token 由全域 CSRFProtect 在正式環境強制；
本 fixture WTF_CSRF_ENABLED=False，CSRFProtect 全域行為由 funlab-flaskr 守護）。
"""
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
APP_NAME='authlogout'
SECRET_KEY='logout-secret'
PREWARM_ENABLED=false
HOME_ENTRY='blank.html'
ENV = '{{{{ENV.T}}}}'
[ENV]
  [ENV.T]
  TESTING = true
  WSGI = 'flask'
  PORT = 5999
  DATABASE = '{{{{DATABASE.T}}}}'
[DATABASE]
  [DATABASE.T]
  url = 'sqlite:///{dbpath}'
[CACHE]
CACHE_TYPE='SimpleCache'
"""

PASSWORD = "***"


@pytest.fixture(scope="module")
def auth_app():
    from funlab.flaskr.app import FunlabFlask
    dbpath = tempfile.mktemp(suffix=".db", dir=os.environ.get("TMPDIR"))
    cfgfile = tempfile.mktemp(suffix=".toml", dir=os.environ.get("TMPDIR"))
    Path(cfgfile).write_text(CFG_TEMPLATE.format(dbpath=dbpath))
    app = FunlabFlask(configfile=cfgfile, envfile=None,
                      import_name="authlogout", template_folder="", static_folder="")
    assert "auth" in app.plugins and str(app.security_mode).endswith("SECURED")
    from funlab.auth.user import UserEntity
    with app.dbmgr.session_context() as s:
        s.add(UserEntity(username="local", email="local@x.io",
                         password=PASSWORD, avatar_url="", state="active"))
    app.config["WTF_CSRF_ENABLED"] = False
    yield app
    app.dbmgr.release()


def _login(c):
    return c.post('/login/', data={'login': '1', 'email': 'local@x.io',
                                   'password': PASSWORD})


def test_get_logout_shows_confirmation_not_logout(auth_app):
    c = auth_app.test_client()
    _login(c)
    r = c.get('/logout')
    assert r.status_code == 200                      # 確認頁，非 302
    assert b"Confirm Logout" in r.data               # 確認按鈕存在
    with c.session_transaction() as sess:
        assert '_user_id' in sess                    # 尚未登出


def test_post_logout_logs_out(auth_app):
    c = auth_app.test_client()
    _login(c)
    r = c.post('/logout')
    assert r.status_code == 302
    with c.session_transaction() as sess:
        assert '_user_id' not in sess


def test_anonymous_get_logout_redirected(auth_app):
    """未登入者 GET /logout 由 login_required 導向登入頁（不渲染確認頁）。"""
    c = auth_app.test_client()
    r = c.get('/logout')
    assert r.status_code == 302
    assert '/login' in r.headers.get('Location', '')


def test_menu_logout_href_still_get_ok(auth_app):
    """紅線防回歸：選單 <a href='/logout'>（GET）仍可用——落到確認頁而非 405。"""
    c = auth_app.test_client()
    _login(c)
    assert c.get('/logout').status_code == 200       # 選單項語意：GET 不再 405/登出
