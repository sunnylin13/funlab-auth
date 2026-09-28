"""funlab-auth 整合測試共用 fixture（IMPROVEMENT_PLAN §0）。

tmp sqlite + test_client；不觸網、不碰正式庫。
兩個關鍵前提：
1. JSONB→sqlite shim：finfun 實體使用 PostgreSQL JSONB，建表前必須註冊 compiles，
   否則 create_all 爆錯。
2. 表單層 CSRF 關閉（WTF_CSRF_ENABLED=False）；全域 CSRFProtect 行為由
   funlab-flaskr 的 tests/test_csrf_protection.py 守護，funlab-auth 不重複測。
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
"""


@pytest.fixture(scope="module")
def auth_app():
    from funlab.flaskr.app import FunlabFlask
    dbpath = tempfile.mktemp(suffix=".db", dir=os.environ.get("TMPDIR"))
    cfgfile = tempfile.mktemp(suffix=".toml", dir=os.environ.get("TMPDIR"))
    Path(cfgfile).write_text(CFG_TEMPLATE.format(dbpath=dbpath))
    app = FunlabFlask(configfile=cfgfile, envfile=None,
                      import_name="authtest", template_folder="", static_folder="")
    assert "auth" in app.plugins and str(app.security_mode).endswith("SECURED")
    app.config["WTF_CSRF_ENABLED"] = False
    yield app
    app.dbmgr.release()


@pytest.fixture(autouse=True)
def _reset_login_rate_limit(request):
    """AUTH-05 相容性：限流計數為 per-app 記憶體態，同 module 多測試共用同 IP
    （127.0.0.1）會互相耗盡額度。每條測試前清零，保持各測試獨立。
    限流本體行為由 tests/integration/test_login_rate.py 專門驗證。"""
    for name in ("auth_app", "app", "auth_app_oauth"):
        if name in request.fixturenames:
            try:
                app = request.getfixturevalue(name)
            except Exception:
                continue
            auth = app.plugins.get("auth") if hasattr(app, "plugins") else None
            if auth is not None and hasattr(auth, "_login_attempts"):
                auth._login_attempts.clear()
