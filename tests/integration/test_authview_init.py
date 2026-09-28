"""AUTH-03 防回歸：[AuthView] 內標量設定鍵不得令 AuthView 初始化炸毀（整站 fail-open PUBLIC）。

規格：docs/IMPROVEMENT_PLAN.md §AUTH-03 (e)。
自建兩個完整 FunlabFlask（tmp sqlite），跑一次約 60–120 秒；不觸網、不碰正式庫。
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
APP_NAME='authtest'
SECRET_KEY='authtest-secret'
PREWARM_ENABLED=false
HOME_ENTRY='blank.html'
ENV = '{{{{ENV.T}}}}'
[ENV]
  [ENV.T]
  TESTING = true
  WSGI = 'flask'
  PORT = 5995
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


def _make_app_with_auth_extra(auth_extra="", name="authtest"):
    from funlab.flaskr.app import FunlabFlask
    dbpath = tempfile.mktemp(suffix=".db", dir=os.environ.get("TMPDIR"))
    cfgfile = tempfile.mktemp(suffix=".toml", dir=os.environ.get("TMPDIR"))
    Path(cfgfile).write_text(CFG_TEMPLATE.format(dbpath=dbpath, auth_extra=auth_extra))
    return FunlabFlask(configfile=cfgfile, envfile=None, import_name=name,
                       template_folder="", static_folder="")


def test_scalar_key_does_not_kill_authview():
    """AUTH-03：[AuthView] 加標量鍵 HOOK_EXAMPLES=true 後 AuthView 仍載入、SECURED、provider 仍註冊。"""
    app = _make_app_with_auth_extra("HOOK_EXAMPLES = true\n", name="authtest-scalar")
    try:
        assert "auth" in app.plugins                       # AuthView 存活
        assert str(app.security_mode).endswith("SECURED")  # 驗證仍生效
        assert list(app.plugins["auth"].oauths) == ["probe_google"]  # provider 仍註冊
    finally:
        app.dbmgr.release()


def test_no_scalar_key_baseline_still_secured():
    """基線防回歸：無標量鍵時行為不變（auth 載入、SECURED、probe_google 註冊）。"""
    app = _make_app_with_auth_extra("", name="authtest-baseline")
    try:
        assert "auth" in app.plugins
        assert str(app.security_mode).endswith("SECURED")
        assert list(app.plugins["auth"].oauths) == ["probe_google"]
    finally:
        app.dbmgr.release()
