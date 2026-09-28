"""AUTH-05 防回歸（PLAN AUTH-05 (e)，Q4 裁示：per-IP + per-email 記憶體計數）：
/login 錯密碼超過 5 次/60 秒 → 429。單進程 waitress 前提；無外部儲存依賴。"""
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
APP_NAME='authrate'
SECRET_KEY='rate-secret'
PREWARM_ENABLED=false
HOME_ENTRY='blank.html'
ENV = '{{{{ENV.T}}}}'
[ENV]
  [ENV.T]
  TESTING = true
  WSGI = 'flask'
  PORT = 6001
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
                      import_name="authrate", template_folder="", static_folder="")
    assert "auth" in app.plugins and str(app.security_mode).endswith("SECURED")
    from funlab.auth.user import UserEntity
    with app.dbmgr.session_context() as s:
        s.add(UserEntity(username="local", email="local@x.io",
                         password="RightPass!1", avatar_url="", state="active"))
    app.config["WTF_CSRF_ENABLED"] = False
    yield app
    app.dbmgr.release()


@pytest.fixture(autouse=True)
def _clear(auth_app):
    auth_app.plugins["auth"]._login_attempts.clear()


def test_sixth_wrong_password_in_window_blocked(auth_app):
    c = auth_app.test_client()
    codes = [c.post('/login/', data={'login': '1', 'email': 'local@x.io',
                                     'password': 'WrongPass!9'}).status_code
             for _ in range(7)]
    assert codes[0] == 200 and codes[1] == 200     # 前 5 次正常處理
    assert codes[5] == 429 and codes[6] == 429     # 第 6、7 次被限流


def test_per_email_bucket_independent_of_ip(auth_app):
    """per-email 桶獨立：換 email 不共享額度（同 IP 下 A 鎖死不影響 B）。"""
    auth = auth_app.plugins["auth"]
    # 預先灌滿 local@x.io 的 acct 桶與共用 ip 桶中 email-A 的計數
    for _ in range(5):
        auth._login_rate_limited(('acct', 'locked@x.io'))
    c = auth_app.test_client()
    # local@x.io 的 acct 桶未滿；ip 桶已因上面 5 次 acct 計數不受影響
    r = c.post('/login/', data={'login': '1', 'email': 'local@x.io',
                                'password': 'WrongPass!9'})
    assert r.status_code == 200


def test_single_wrong_password_not_blocked(auth_app):
    """附錄 A 相容性：單次錯密碼嘗試不受影響（200 渲染登入頁）。"""
    c = auth_app.test_client()
    r = c.post('/login/', data={'login': '1', 'email': 'local@x.io',
                                'password': 'WrongPass!9'})
    assert r.status_code == 200


def test_state_bloat_pruning(auth_app):
    """PLAN (d)：狀態容器 >10000 鍵時修剪過期桶，防無限膨脹。"""
    import time
    auth = auth_app.plugins["auth"]
    auth._login_attempts.clear()
    now = time.time()
    # 灌 10001 個鍵：一半過期、一半新鮮
    for i in range(10001):
        if i % 2:
            auth._login_attempts[('acct', f'stale{i}')] = [now - 9999]
        else:
            auth._login_attempts[('acct', f'fresh{i}')] = [now]
    auth._login_rate_limited(('acct', 'trigger'))
    assert len(auth._login_attempts) <= 5002   # 過期桶被清掉
    auth._login_attempts.clear()
