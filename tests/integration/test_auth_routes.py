"""funlab-auth 路由層級防回歸整合測試。

防回歸範圍（對應 2026-09 熱修 H2/H3）：
- /login 錯誤密碼不可登入（H2 前：email 存在即登入）
- /login 未勾 rememberme 不可 400（H2 前：rememberme 用 request.form[...]）
- OAuth 佔位密碼不可用於密碼登入（check_password_login → LOGIN_EXTERNAL_ACCOUNT）
- /resetpass 匿名不可操作（H3 前：匿名即可改任何人密碼）
- /resetpass 不可改他人密碼
- /resetpass OAuth 帳號不可設密碼
- /resetpass 正確流程：舊密碼驗證 → 改密 → 登出

需要完整 FunlabFlask（plugin 註冊、login_manager、SQLite tmp 庫）。
執行：cd funlab-auth && python -m pytest -q tests/integration/test_auth_routes.py
注意：本檔建立 FunlabFlask 需 finfun 環境（entry point plugins 全部載入），
      跑一次約 30–60 秒；不觸網、不碰正式庫（tmp sqlite）。
"""
import base64
import os
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# SQLite 無法原生編譯 JSONB（finfun 實體用了 PostgreSQL 型別）；
# 建立 app 前註冊 compile shim，讓 create_all 在 sqlite 上可行。
# ---------------------------------------------------------------------------
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
APP_NAME='authregress'
SECRET_KEY='regress-secret'
PREWARM_ENABLED=false
HOME_ENTRY='blank.html'
ENV = '{{{{ENV.T}}}}'
[ENV]
  [ENV.T]
  TESTING = true
  WSGI = 'flask'
  PORT = 5997
  DATABASE = '{{{{DATABASE.T}}}}'
[DATABASE]
  [DATABASE.T]
  url = 'sqlite:///{dbpath}'
[CACHE]
CACHE_TYPE='SimpleCache'
"""


@pytest.fixture(scope="module")
def auth_app():
    """tmp sqlite 上的完整 FunlabFlask（含 AuthView plugin）。"""
    from funlab.flaskr.app import FunlabFlask

    dbpath = tempfile.mktemp(suffix=".db", dir=os.environ.get("TMPDIR"))
    cfgfile = tempfile.mktemp(suffix=".toml", dir=os.environ.get("TMPDIR"))
    Path(cfgfile).write_text(CFG_TEMPLATE.format(dbpath=dbpath))
    app = FunlabFlask(configfile=cfgfile, envfile=None,
                      import_name="authregress", template_folder="", static_folder="")
    assert "auth" in app.plugins, "AuthView 必須被註冊（防回歸前提）"
    assert str(app.security_mode).endswith("SECURED"), "security_mode 必須為 SECURED"
    # 表單層 CSRF 關閉以簡化測試（CSRFProtect 全域行為由 funlab-flaskr 的
    # tests/test_csrf_protection.py 單獨守護）
    app.config["WTF_CSRF_ENABLED"] = False
    yield app
    app.dbmgr.release()


@pytest.fixture()
def seeded(auth_app):
    """每模組一組固定種子帳號：local（可密碼登入）、gone、oauth（佔位密碼）、disabled。"""
    from funlab.auth.user import OAuthUser, UserEntity
    from sqlalchemy import select

    with auth_app.dbmgr.session_context() as s:
        created = []
        emails = {"local@x.io", "gone@x.io", "g@x.io", "off@x.io"}
        for e in emails:
            if s.execute(select(UserEntity).where(UserEntity.email == e)).scalar():
                break
        else:
            s.add(UserEntity(username="local", email="local@x.io",
                             password="RightPass!1", avatar_url="", state="active"))
            s.add(UserEntity(username="gone", email="gone@x.io",
                             password="RightPass!1", avatar_url="", state="active"))
            s.add(UserEntity(username="off", email="off@x.io",
                             password="RightPass!1", avatar_url="", state="disabled"))
            s.add(OAuthUser("g@x.io", "g", None, "", "active").to_userentity())
            created = list(emails)
    return auth_app


def _login(client, email, password, rememberme=None):
    data = {"login": "1", "email": email, "password": password}
    if rememberme is not None:
        data["rememberme"] = rememberme
    return client.post("/login/", data=data)


def _flash_text(client):
    with client.session_transaction() as sess:
        msgs = [m for _, m in sess.get("_flashes", [])]
        sess.pop("_flashes", None)
        return " | ".join(msgs)


class TestLoginRegression:
    def test_wrong_password_is_rejected(self, seeded):
        r = _login(seeded.test_client(), "local@x.io", "WRONG")
        assert r.status_code == 200
        assert b"password" in r.data.lower() or b"incorrect" in r.data.lower()

    def test_wrong_password_does_not_create_session(self, seeded):
        c = seeded.test_client()
        _login(c, "local@x.io", "WRONG")
        with c.session_transaction() as sess:
            assert "_user_id" not in sess

    def test_correct_password_logs_in(self, seeded):
        r = _login(seeded.test_client(), "local@x.io", "RightPass!1")
        assert r.status_code == 302

    def test_login_without_rememberme_field_is_200_not_400(self, seeded):
        # 瀏覽器未勾 checkbox 時完全不送 rememberme 欄位
        r = _login(seeded.test_client(), "local@x.io", "RightPass!1")
        assert r.status_code == 302

    def test_rememberme_checked_sets_remember_cookie(self, seeded):
        r = _login(seeded.test_client(), "local@x.io", "RightPass!1", "y")
        cookies = ";".join(v for k, v in r.headers if k.lower() == "set-cookie")
        assert "remember" in cookies

    def test_rememberme_unchecked_sets_no_remember_cookie(self, seeded):
        r = _login(seeded.test_client(), "local@x.io", "RightPass!1")
        cookies = ";".join(v for k, v in r.headers if k.lower() == "set-cookie")
        assert "remember" not in cookies

    def test_oauth_placeholder_password_cannot_log_in(self, seeded):
        c = seeded.test_client()
        r = _login(c, "g@x.io", "RightPass!1")
        assert b"external authentication provider" in r.data
        with c.session_transaction() as sess:
            assert "_user_id" not in sess

    def test_known_placeholder_string_cannot_log_in(self, seeded):
        c = seeded.test_client()
        r = _login(c, "g@x.io",
                   "account+is+from+external+authentication+provider!!!")
        assert b"external authentication provider" in r.data
        with c.session_transaction() as sess:
            assert "_user_id" not in sess

    def test_disabled_user_cannot_log_in(self, seeded):
        c = seeded.test_client()
        _login(c, "off@x.io", "RightPass!1")
        with c.session_transaction() as sess:
            assert "_user_id" not in sess


class TestResetpassRegression:
    def test_anonymous_is_redirected_to_login(self, seeded):
        c = seeded.test_client()
        r = c.post("/resetpass", data={"resetpass": "1", "email": "local@x.io",
                                       "old_password": "x", "new_password": "N",
                                       "confirm_password": "N"})
        assert r.status_code == 302
        assert "/login" in r.headers.get("Location", "")

    def test_cannot_change_other_users_password(self, seeded):
        c = seeded.test_client()
        _login(c, "local@x.io", "RightPass!1")
        r = c.post("/resetpass", data={"resetpass": "1", "email": "g@x.io",
                                   "old_password": "x", "new_password": "hacked",
                                   "confirm_password": "hacked"})
        # AUTH-13（C3）後 resetpass.html 渲染 flash 區塊：渲染即消費 session
        # flash，斷言升級為 body 層（PLAN AUTH-13 (f) 附錄 A 相容性調整）
        assert "your own password" in r.data.decode("utf-8", "replace")
        from funlab.auth.utils import load_user
        with seeded.dbmgr.session_context() as s:
            assert load_user("g@x.io", s).verify_pass("hacked") is False

    def test_oauth_account_cannot_set_password(self, seeded):
        c = seeded.test_client()
        # 以 session 注入方式模擬已登入的 OAuth 使用者 g
        from funlab.auth.utils import load_user
        with seeded.dbmgr.session_context() as s:
            gid = load_user("g@x.io", s).id
        with c.session_transaction() as sess:
            sess["_user_id"] = str(gid)
            sess["_fresh"] = True
        r = c.post("/resetpass", data={"resetpass": "1", "email": "g@x.io",
                                   "old_password": "x", "new_password": "hacked",
                                   "confirm_password": "hacked"})
        # AUTH-13（C3）後：flash 由模板消費，斷言升級為 body 層
        assert "external authentication provider" in r.data.decode("utf-8", "replace")
        with seeded.dbmgr.session_context() as s:
            from funlab.auth.utils import load_user
            assert load_user("g@x.io", s).verify_pass("hacked") is False

    def test_wrong_old_password_rejected(self, seeded):
        c = seeded.test_client()
        _login(c, "local@x.io", "RightPass!1")
        c.post("/resetpass", data={"resetpass": "1", "email": "local@x.io",
                                   "old_password": "bad", "new_password": "N3w!",
                                   "confirm_password": "N3w!"})
        with seeded.dbmgr.session_context() as s:
            from funlab.auth.utils import load_user
            assert load_user("local@x.io", s).verify_pass("N3w!") is False

    def test_mismatch_confirm_rejected(self, seeded):
        c = seeded.test_client()
        _login(c, "local@x.io", "RightPass!1")
        r = c.post("/resetpass", data={"resetpass": "1", "email": "local@x.io",
                                       "old_password": "RightPass!1",
                                       "new_password": "N3w!",
                                       "confirm_password": "OTHER"})
        assert r.status_code == 200

    def test_correct_flow_changes_password_and_logs_out(self, seeded):
        c = seeded.test_client()
        _login(c, "local@x.io", "RightPass!1")
        r = c.post("/resetpass", data={"resetpass": "1", "email": "local@x.io",
                                       "old_password": "RightPass!1",
                                       "new_password": "N3wPass!2",
                                       "confirm_password": "N3wPass!2"})
        assert b"Password reset successfully" in r.data
        with c.session_transaction() as sess:
            assert "_user_id" not in sess  # 成功後必須登出
        # 新密碼可登入、舊密碼失效（測完還原，避免污染其他測試）
        r2 = _login(seeded.test_client(), "local@x.io", "N3wPass!2")
        assert r2.status_code == 302
        c2 = seeded.test_client()
        _login(c2, "local@x.io", "N3wPass!2")
        c2.post("/resetpass", data={"resetpass": "1", "email": "local@x.io",
                                    "old_password": "N3wPass!2",
                                    "new_password": "RightPass!1",
                                    "confirm_password": "RightPass!1"})
