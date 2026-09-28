"""funlab-auth 未修缺陷重現測試（IMPROVEMENT_PLAN.md AUTH-01…AUTH-12 佐證）。

特性：斷言的是「現行（有缺陷）行為」——本檔全部 PASS 即代表缺陷存在。
修好對應 AUTH-## 後，本檔對應測試會 FAIL（= 修復生效信號），屆時應將該測試
反轉為防回歸斷言（文件各項已給出反轉後的版本）。

狀態（C3 2026-09-28）：AUTH-01 三條、AUTH-03 一條（R1 收尾）、AUTH-02/04×2/
05/07×2、AUTH-12 註冊鎖死路徑（B3）、AUTH-06/08/11（C3）已按 PLAN (e) 反轉為
防回歸斷言（修復已合併 main／本 PR）；其餘測試仍為缺陷重現，待對應修復合併後反轉。

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


PASSWORD = "**" + "Right"   # 與上方 fixture 種子帳號 probe@x.io 的密碼一致
                            # （原值多一個 * 致登入失敗，舊缺陷斷言 GET=302 屬僥倖 PASS）


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
    """AUTH-02 防回歸（B3 修復後反轉，PLAN AUTH-02 (e) 反轉版；Q3 裁示
    ALLOW_REGISTER 預設 false＋邀請制）：匿名不可註冊。
    （原為缺陷重現斷言「匿名可註冊即用」；B3 修復後按 PLAN §0 反轉。）"""

    def test_anonymous_cannot_register(self, app):
        c = app.test_client()
        r = c.post("/register", data={"register": "1", "username": "mallory",
                                      "email": "mallory2@x.io", "password": "***"})
        assert r.status_code == 302                  # 導向登入，不建立帳號
        r2 = c.post("/login/", data={"login": "1", "email": "mallory2@x.io",
                                     "password": "***"})
        assert b"Invalid email or password" in r2.data  # 帳號未被建立（AUTH-06 統一訊息）


class TestAUTH04_RequestLoaderBearerBranch:
    """AUTH-04 防回歸（B3 修復後反轉，PLAN AUTH-04 (e) 反轉版）：
    任意 Bearer/google_token 走 unauthorized 流程（302/401），絕不 500。
    （原為缺陷重現斷言「== 500」；B3 修復後按 PLAN §0 反轉。）"""

    def test_arbitrary_bearer_header_never_500(self, app):
        app.plugins["auth"].oauth_name_inuse = "probe_google"
        try:
            r = app.test_client().get("/settings",
                                      headers={"Authorization": "***"})
            assert r.status_code in (302, 401)   # 拒絕但不 500
        finally:
            app.plugins["auth"].oauth_name_inuse = None

    def test_google_token_query_param_never_500(self, app):
        app.plugins["auth"].oauth_name_inuse = "probe_google"
        try:
            r = app.test_client().get("/settings?google_token=***")
            assert r.status_code in (302, 401)
        finally:
            app.plugins["auth"].oauth_name_inuse = None


class TestAUTH0506_BruteForceAndEnumeration:
    """AUTH-05 防回歸（B3 修復後反轉，PLAN AUTH-05 (e)；Q4 裁示 per-IP+per-email
    記憶體計數）；AUTH-06（未修）仍為缺陷重現。"""

    def test_sixth_wrong_password_locked_out(self, app):
        c = app.test_client()
        codes = [c.post("/login/", data={"login": "1", "email": "probe@x.io",
                                         "password": "***"}).status_code
                 for _ in range(20)]
        assert codes[0] == 200                       # 首次正常處理
        assert 429 in codes                          # 修復後：超窗必見 429
        assert set(codes) <= {200, 429}

    def test_existence_messages_identical(self, app):
        """AUTH-06 防回歸（C3 修復後反轉，PLAN AUTH-06 (e) 反轉版）：
        不存在與錯密碼共用同一訊息，杜絕列舉。
        （原為缺陷重現斷言「兩訊息不同→可列舉」；C3 修復後按 PLAN §0 反轉。）"""
        c = app.test_client()
        # 注意：本 app 無限流清零 fixture，先前測試已灌滿 ip 桶 → 先清
        app.plugins["auth"]._login_attempts.clear()
        r1 = c.post("/login/", data={"login": "1", "email": "ghost@x.io",
                                     "password": "***"})
        app.plugins["auth"]._login_attempts.clear()
        r2 = c.post("/login/", data={"login": "1", "email": "probe@x.io",
                                     "password": "***"})
        assert b"Invalid email or password" in r1.data
        assert b"Invalid email or password" in r2.data
        assert b"User email not exist" not in r1.data


class TestAUTH07_GetLogout:
    """AUTH-07 防回歸（B3 修復後反轉，PLAN AUTH-07 (e) 反轉版）：
    GET 顯示確認頁不登出；POST 才登出（CSRF 由全域 CSRFProtect 於正式環境強制）。
    （原為缺陷重現斷言「GET=302 登出 / POST=405」；B3 修復後按 PLAN §0 反轉。）"""

    def test_logout_get_shows_confirmation_not_logout(self, app):
        c = app.test_client()
        c.post("/login/", data={"login": "1", "email": "probe@x.io", "password": PASSWORD})
        assert c.get("/logout").status_code == 200   # 確認頁，非直接登出
        with c.session_transaction() as sess:
            assert "_user_id" in sess                # session 仍存活

    def test_logout_post_logs_out(self, app):
        c = app.test_client()
        c.post("/login/", data={"login": "1", "email": "probe@x.io", "password": PASSWORD})
        assert c.post("/logout").status_code == 302
        with c.session_transaction() as sess:
            assert "_user_id" not in sess


class TestAUTH08_SessionRotation:
    """AUTH-08 防回歸（C3 修復後反轉，PLAN AUTH-08 (e) 反轉版）：
    登入手勢清空匿名期殘留鍵。
    （原為缺陷重現斷言「植入鍵跨過登入存活」；C3 修復後按 PLAN §0 反轉。）"""

    def test_prelogin_session_key_cleared_on_login(self, app):
        c = app.test_client()
        with c.session_transaction() as sess:
            sess["attacker_key"] = "planted"
        c.post("/login/", data={"login": "1", "email": "probe@x.io", "password": PASSWORD})
        with c.session_transaction() as sess:
            assert "attacker_key" not in sess
            assert "_user_id" in sess


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

    def test_is_anonymous_none_role_no_raise(self):
        """AUTH-11 防回歸（C3 修復後反轉，PLAN AUTH-11 (e) 反轉版）：
        role=None 不raise（詳見 tests/unit/test_user_props.py）。
        （原為缺陷重現斷言 pytest.raises(AttributeError)。）"""
        from funlab.auth.user import User
        u = User(email="a@b.io", username="a", password="***",
                 avatar_url="", state="active")
        u.role = None
        assert u.is_anonymous is False

    def test_register_with_placeholder_password_locks_account(self, app):
        """AUTH-12 原缺陷路徑已被 AUTH-02 預設關閉註冊封死（B3）：
        註冊關閉 → 帳號未建立 → 登入不可能被導向 external。保留防禦斷言。"""
        from funlab.auth.user import EXTERNAL_AUTH_PLACEHOLDER
        c = app.test_client()
        c.post("/register", data={"register": "1", "username": "tricky",
                                  "email": "tricky@x.io",
                                  "password": EXTERNAL_AUTH_PLACEHOLDER})
        r = c.post("/login/", data={"login": "1", "email": "tricky@x.io",
                                    "password": EXTERNAL_AUTH_PLACEHOLDER})
        # 修復後：註冊被拒（預設 ALLOW_REGISTER=false），帳號不存在
        assert b"Invalid email or password" in r.data  # AUTH-06 統一訊息
