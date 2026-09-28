"""C3（Wave3 P2）加固防回歸測試——PLAN AUTH-06/08/09/13/14 (e) 規格版。

一檔一主題會拖太多個 FunlabFlask 實例；本檔用單一 module-scoped app
（tmp sqlite）覆蓋 login 訊息/ session 輪換 / next 白名單 / flash 可見 /
OAuth 例外不外洩 五個路由層級斷言。AUTH-11 為模型層純單元測試，
另立 tests/unit/test_user_props.py。

執行：cd funlab-auth && python -m pytest -q tests/integration/test_c3_auth_hardening.py
"""
import os
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(element, compiler, **kw):  # pragma: no cover
    return "JSON"


os.environ.setdefault("QT_API", "None")
os.environ.setdefault("MPLBACKEND", "Agg")

pytestmark = pytest.mark.integration

PASSWORD = "RightPass" + "!1"

CFG_TEMPLATE = """
[FunlabFlask]
APP_NAME='authc3'
SECRET_KEY='c3-secret'
PREWARM_ENABLED=false
HOME_ENTRY='blank.html'
ENV = '{{{{ENV.T}}}}'
[ENV]
  [ENV.T]
  TESTING = true
  WSGI = 'flask'
  PORT = 6010
  DATABASE = '{{{{DATABASE.T}}}}'
[DATABASE]
  [DATABASE.T]
  url = 'sqlite:///{dbpath}'
[CACHE]
CACHE_TYPE='SimpleCache'
[AuthView]
  [AuthView.probe_google]
  provider = 'google'
  userinfo_key_mapping = {{ username = 'name', avatar_url = 'picture' }}
  client_id = 'fake-client-id'
  client_secret = 'fake-secret'
  authorize_url = 'https://nonexistent.invalid/oauth/authorize'
  access_token_url = 'https://nonexistent.invalid/oauth/token'
  userinfo_endpoint = 'https://nonexistent.invalid/oauth/userinfo'
"""


@pytest.fixture(scope="module")
def auth_app():
    from funlab.flaskr.app import FunlabFlask
    dbpath = tempfile.mktemp(suffix=".db", dir=os.environ.get("TMPDIR"))
    cfgfile = tempfile.mktemp(suffix=".toml", dir=os.environ.get("TMPDIR"))
    Path(cfgfile).write_text(CFG_TEMPLATE.format(dbpath=dbpath))
    app = FunlabFlask(configfile=cfgfile, envfile=None,
                      import_name="authc3", template_folder="", static_folder="")
    assert "auth" in app.plugins and str(app.security_mode).endswith("SECURED")
    from funlab.auth.user import UserEntity
    with app.dbmgr.session_context() as s:
        s.add(UserEntity(username="local", email="local@x.io",
                         password=PASSWORD, avatar_url="", state="active"))
        s.add(UserEntity(username="off", email="off@x.io",
                         password=PASSWORD, avatar_url="", state="disabled"))
    app.config["WTF_CSRF_ENABLED"] = False
    yield app
    app.dbmgr.release()


def _login(c, email="local@x.io", pw=PASSWORD):
    return c.post("/login/", data={"login": "1", "email": email,
                                   "password": pw})


# ---------------------------------------------------------------------------
# AUTH-06：不存在與錯密碼共用同一訊息，杜絕列舉（PLAN (d)/(e)）
# ---------------------------------------------------------------------------

def test_nonexistent_and_wrong_password_same_message(auth_app):
    c = auth_app.test_client()
    r1 = _login(c, email="ghost@x.io", pw="WRONG-o" + "nce")
    r2 = _login(c, email="local@x.io", pw="RIGHT-" + "wrong")
    assert b"Invalid email or password" in r1.data and b"Invalid email or password" in r2.data
    assert b"User email not exist" not in r1.data
    assert b"Incorrect password" not in r2.data


def test_inactive_message_kept_and_oauth_message_kept(auth_app):
    """PLAN (d) 註：LOGIN_INACTIVE／LOGIN_EXTERNAL_ACCOUNT 訊息保留。"""
    c = auth_app.test_client()
    r = _login(c, email="off@x.io", pw=PASSWORD)
    assert b"Account is not active" in r.data
    assert b"Invalid email or password" not in r.data


# ---------------------------------------------------------------------------
# AUTH-08：登入手勢清空匿名期 session（PLAN (d)/(e)）
# ---------------------------------------------------------------------------

def test_prelogin_key_cleared_on_login(auth_app):
    c = auth_app.test_client()
    with c.session_transaction() as sess:
        sess["attacker_key"] = "planted"
    _login(c)
    with c.session_transaction() as sess:
        assert "attacker_key" not in sess and "_user_id" in sess


# ---------------------------------------------------------------------------
# AUTH-09：next 只跟本站相對路徑（PLAN (d)/(e)）
# ---------------------------------------------------------------------------

def test_external_url_in_next_is_ignored(auth_app):
    c = auth_app.test_client()
    r = c.post("/login/?next=https://evil.example.com/pw?d=",
               data={"login": "1", "email": "local@x.io", "password": PASSWORD})
    assert r.status_code == 302
    assert urlsplit(r.headers["Location"]).path == "/home"   # 絕不跳外部


def test_scheme_relative_next_is_ignored(auth_app):
    """紅線（PLAN (g)）：//evil.com 協議相對形式必須擋掉。"""
    c = auth_app.test_client()
    r = c.post("/login/?next=//evil.com/x",
               data={"login": "1", "email": "local@x.io", "password": PASSWORD})
    assert urlsplit(r.headers["Location"]).path == "/home"


def test_relative_next_followed(auth_app):
    c = auth_app.test_client()
    r = c.post("/login/?next=/settings",
               data={"login": "1", "email": "local@x.io", "password": PASSWORD})
    assert r.headers["Location"] == "/settings"


def test_unauthorized_next_absolute_url_is_safe_after_login(auth_app):
    """AUTH-09 根因：unauthorized_handler 塞的是絕對 URL；登入成功後
    經 _safe_next 一律回落本站（現況不跟隨→修復後跟隨也安全）。"""
    c = auth_app.test_client()
    r = c.post("/login/?next=http://localhost/settings",
               data={"login": "1", "email": "local@x.io", "password": PASSWORD})
    assert urlsplit(r.headers["Location"]).path == "/home"


# ---------------------------------------------------------------------------
# AUTH-13：模板 flash 區塊可見（PLAN (d)/(e)）
# ---------------------------------------------------------------------------

def test_resetpass_rejection_flash_visible_in_body(auth_app):
    c = auth_app.test_client()
    _login(c)
    r = c.post("/resetpass", data={"resetpass": "1", "email": "other@x.io",
                                   "old_password": "x", "new_password": "N",
                                   "confirm_password": "N"})
    assert b"your own password" in r.data       # 修復前：只在 session，body 無此字樣


def test_register_template_has_flash_block(auth_app):
    """PLAN (e) register 面： ALLOW_REGISTER 預設 false 無法走重複 email
    路徑，改以模板層斷言 flash 區塊存在（紅線 (g)：只准新增 flash 區塊）。"""
    from funlab.auth.view import AuthView  # noqa: F401  確保模板隨包可解析
    import funlab.auth as pkg
    tpl = Path(next(iter(pkg.__path__))) / "templates" / "register.html"
    text = tpl.read_text(encoding="utf-8")
    assert "get_flashed_messages" in text
    reset = (Path(next(iter(pkg.__path__))) / "templates" / "resetpass.html").read_text(encoding="utf-8")
    assert "get_flashed_messages" in reset


# ---------------------------------------------------------------------------
# AUTH-14：/authorize 例外細節不外洩（PLAN (d)/(e)）
# ---------------------------------------------------------------------------

def test_oauth_failure_flash_has_no_exception_text(auth_app):
    # GET /authorize/probe_google 無 code 參數 → 失敗路徑
    r = auth_app.test_client().get("/authorize/probe_google")
    assert r.status_code == 200
    assert b"Exception:" not in r.data
    assert b"OAuth sign-in failed" in r.data


def test_oauth_token_not_stored_in_session(auth_app):
    """AUTH-14：access_token 不再明文進簽名 cookie（全 workspace 無消費者，
    PLAN (d)：可逕行移除）。以源碼級斷言鎖住，防回歸。"""
    import funlab.auth.view as v
    import inspect
    src = inspect.getsource(v)
    assert "session['oauth_token'] = token" not in src and 'session["oauth_token"] = token' not in src
