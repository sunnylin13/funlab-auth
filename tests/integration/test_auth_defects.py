"""funlab-auth 未修缺陷重現測試（IMPROVEMENT_PLAN.md AUTH-01…AUTH-12 佐證）。

特性：斷言的是「現行（有缺陷）行為」——本檔全部 PASS 即代表缺陷存在。
修好對應 AUTH-## 後，本檔對應測試會 FAIL（= 修復生效信號），屆時應將該測試
反轉為防回歸斷言（文件各項已給出反轉後的版本）。

狀態（R1 收尾 2026-09-28）：AUTH-01 三條與 AUTH-03 一條已按 PLAN (e) 反轉為
防回歸斷言（A4/A6-1 修復已合併 main）；其餘測試仍為缺陷重現，待對應修復合併後反轉。

執行（需要 finfun 環境；tmp sqlite，不觸網、不碰正式庫）：
    cd funlab-auth && source ~/.venv/fund13/bin/activate
    python -m pytest -q <本檔路徑>
注意：本檔建 2 個完整 FunlabFlask，跑一次約 60–120 秒。
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

CFG_TEMPLATE = """
[FunlabFlask]
APP_NAME='authdefect'
SECRET_KEY='defect-secret'
PREWARM_ENABLED=false
HOME_ENTRY='blank.html'
ENV = '{{{{ENV.T}}}}'
[ENV]
  [ENV.T]
  TESTING = true
  WSGI = 'flask'
  PORT = 5996
  DATABASE = '{{{{DATABASE.T}}}}'
[DATABASE]
  [DATABASE.T]
  url = 'sqlite:///{dbpath}'
[CACHE]
CACHE_TYPE='SimpleCache'
[AuthView]
{auth_extra}
  [AuthView.probe_google]
  provider = 'google'
  userinfo_key_mapping = {{ username = 'name', avatar_url = 'picture' }}
  client_id = 'fake-client-id'
  client_secret = 'fake-secret'
  authorize_url = 'https://nonexistent.invalid/oauth/authorize'
  access_token_url = 'https://nonexistent.invalid/oauth/token'
  userinfo_endpoint = 'https://nonexistent.invalid/oauth/userinfo'
"""


def _make_app(name, auth_extra=""):
    from funlab.flaskr.app import FunlabFlask
    dbpath = tempfile.mktemp(suffix=".db", dir=os.environ.get("TMPDIR"))
    cfgfile = tempfile.mktemp(suffix=".toml", dir=os.environ.get("TMPDIR"))
    Path(cfgfile).write_text(CFG_TEMPLATE.format(dbpath=dbpath, auth_extra=auth_extra))
    return FunlabFlask(configfile=cfgfile, envfile=None, import_name=name,
                       template_folder="", static_folder="")


@pytest.fixture(scope="module")
def app():
    a = _make_app("authdefect")
    from funlab.auth.user import OAuthUser, UserEntity
    with a.dbmgr.session_context() as s:
        s.add(UserEntity(username="probe", email="probe@x.io",
                         password="**" + "Right", avatar_url="", state="active"))
    a.config["WTF_CSRF_ENABLED"] = False
    yield a
    a.dbmgr.release()


PASSWORD = "***" + "Right"


class TestAUTH01_UsersLoaderNoneGuard:
    """AUTH-01（L9）防回歸（R1 收尾反轉，PLAN AUTH-01 (e) 反轉版）：
    user_loader/request_loader 對已刪除使用者回 None → 匿名+unauthorized 流程，絕不 500。
    （原為缺陷重現斷言「== 500」；A4 修復合併 main@81d519f 後按 PLAN §0 反轉。）"""

    def test_deleted_user_cookie_anonymous_not_500(self, app):
        c = app.test_client()
        with c.session_transaction() as sess:
            sess["_user_id"] = "99999"   # 已刪除使用者的舊 cookie
            sess["_fresh"] = True
        assert c.get("/login/").status_code in (200, 302)  # 匿名處理，絕不 500

    def test_user_loader_callback_returns_none(self, app):
        assert app.login_manager._user_callback("99999") is None  # 回 None 走匿名流程

    def test_request_loader_stale_user_id_not_500(self, app):
        c = app.test_client()
        with c.session_transaction() as sess:
            sess["user_id"] = "99999"    # request_loader 的 session 分支
        assert c.get("/settings").status_code in (200, 302)  # 302 導向登入，非 500


class TestAUTH02_OpenRegistration:
    """AUTH-02（L10）：/register 匿名開放，註冊即用。"""

    def test_anonymous_can_register_and_login(self, app):
        c = app.test_client()
        r = c.post("/register", data={"register": "1", "username": "mallory",
                                      "email": "mallory@x.io", "password": "***"})
        assert b"Account is created successfully" in r.data  # 修復後（預設關閉）應被拒
        r2 = c.post("/login/", data={"login": "1", "email": "mallory@x.io",
                                     "password": "***"})
        assert r2.status_code == 302     # 新帳號立即取得登入權限


class TestAUTH04_RequestLoaderBearerBranch:
    """AUTH-04：Authorization/google_token 直接打 provider userinfo，失敗炸 500。"""

    def test_arbitrary_bearer_header_crashes_request_loader(self, app):
        app.plugins["auth"].oauth_name_inuse = "probe_google"
        try:
            r = app.test_client().get("/settings",
                                      headers={"Authorization": "***"})
            assert r.status_code == 500  # 修復後應為 401/302，非 500
        finally:
            app.plugins["auth"].oauth_name_inuse = None

    def test_google_token_query_param_crashes(self, app):
        app.plugins["auth"].oauth_name_inuse = "probe_google"
        try:
            r = app.test_client().get("/settings?google_token=***")
            assert r.status_code == 500
        finally:
            app.plugins["auth"].oauth_name_inuse = None


class TestAUTH0506_BruteForceAndEnumeration:
    """AUTH-05 無速率限制；AUTH-06 列舉訊息可區分帳號是否存在。"""

    def test_twenty_wrong_passwords_never_locked_out(self, app):
        c = app.test_client()
        codes = {c.post("/login/", data={"login": "1", "email": "probe@x.io",
                                         "password": "***"}).status_code
                 for _ in range(20)}
        assert codes == {200}            # 無任何 429/鎖定

    def test_existence_messages_differ(self, app):
        c = app.test_client()
        r1 = c.post("/login/", data={"login": "1", "email": "ghost@x.io",
                                     "password": "***"})
        r2 = c.post("/login/", data={"login": "1", "email": "probe@x.io",
                                     "password": "***"})
        assert b"User email not exist" in r1.data
        assert b"User email not exist" not in r2.data  # 兩訊息不同 → 可列舉


class TestAUTH07_GetLogout:
    """AUTH-07：logout 為 GET（CSRFProtect 不覆蓋 GET）→ 跨站強制登出。"""

    def test_logout_works_via_get(self, app):
        c = app.test_client()
        c.post("/login/", data={"login": "1", "email": "probe@x.io", "password": PASSWORD})
        assert c.get("/logout").status_code == 302   # 修復後 GET 應 405，僅 POST

    def test_logout_post_not_supported(self, app):
        c = app.test_client()
        c.post("/login/", data={"login": "1", "email": "probe@x.io", "password": PASSWORD})
        assert c.post("/logout").status_code == 405


class TestAUTH08_SessionNotRotated:
    """AUTH-08：登入不清 session 舊鍵（登入前植入的鍵跨過登入存活）。"""

    def test_prelogin_session_key_survives_login(self, app):
        c = app.test_client()
        with c.session_transaction() as sess:
            sess["attacker_key"] = "planted"
        c.post("/login/", data={"login": "1", "email": "probe@x.io", "password": PASSWORD})
        with c.session_transaction() as sess:
            assert "attacker_key" in sess  # 修復後 session.clear() 應清掉


@pytest.mark.parametrize("auth_extra,expected_loaded", [
    ("HOOK_EXAMPLES = true\n", True),    # 標量鍵被跳過 → AuthView 存活（fail-closed）
])
def test_AUTH03_scalar_config_key_keeps_authview_secured(auth_extra, expected_loaded):
    """AUTH-03 防回歸（R1 收尾反轉，PLAN AUTH-03 (e) 反轉版）：
    [AuthView] 標量鍵不再炸毀 AuthView 初始化 → 驗證仍生效（SECURED），provider 仍註冊。
    （原為缺陷重現斷言「auth 未載入 + PUBLIC」；A6-1 修復合併 main 後按 PLAN §0 反轉。）"""
    a = _make_app("authdefect3", auth_extra=auth_extra)
    try:
        assert ("auth" in a.plugins) is expected_loaded
        assert str(a.security_mode).endswith("SECURED")
        assert list(a.plugins["auth"].oauths) == ["probe_google"]  # provider 仍註冊
    finally:
        a.dbmgr.release()


class TestAUTH11_12_UserModel:
    """AUTH-11：role=None → is_anonymous 崩潰；AUTH-12：佔位密碼自我鎖死。"""

    def test_is_anonymous_raises_when_role_none(self):
        from funlab.auth.user import User
        u = User(email="a@b.io", username="a", password="***",
                 avatar_url="", state="active")
        u.role = None
        with pytest.raises(AttributeError):
            u.is_anonymous               # 修復後應回 False/True，不raise

    def test_register_with_placeholder_password_locks_account(self, app):
        from funlab.auth.user import EXTERNAL_AUTH_PLACEHOLDER
        c = app.test_client()
        c.post("/register", data={"register": "1", "username": "tricky",
                                  "email": "tricky@x.io",
                                  "password": EXTERNAL_AUTH_PLACEHOLDER})
        r = c.post("/login/", data={"login": "1", "email": "tricky@x.io",
                                    "password": EXTERNAL_AUTH_PLACEHOLDER})
        # 用自己剛註冊的密碼登入 → 被判定 external account → 永遠無法密碼登入（自我鎖死）
        assert b"external authentication provider" in r.data
