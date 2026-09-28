"""AUTH-04 防回歸（PLAN AUTH-04 (e)）：request_loader OAuth Authorization 分支。

任意 Bearer token / ?google_token= 一律走 unauthorized 流程（302/401），絕不 500、
絕不把例外升格成 500。app 的 [AuthView] 含指向 https://nonexistent.invalid/...
的假 provider（附錄 B fixture 慣例），不觸網（DNS 必失敗＝外呼必失敗路徑）。
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
APP_NAME='authreqloader'
SECRET_KEY='reqloader-secret'
PREWARM_ENABLED=false
HOME_ENTRY='blank.html'
ENV = '{{{{ENV.T}}}}'
[ENV]
  [ENV.T]
  TESTING = true
  WSGI = 'flask'
  PORT = 5998
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
def auth_app_oauth():
    """附錄 B fixture：含假 OAuth provider 的完整 FunlabFlask（tmp sqlite）。"""
    from funlab.flaskr.app import FunlabFlask
    dbpath = tempfile.mktemp(suffix=".db", dir=os.environ.get("TMPDIR"))
    cfgfile = tempfile.mktemp(suffix=".toml", dir=os.environ.get("TMPDIR"))
    Path(cfgfile).write_text(CFG_TEMPLATE.format(dbpath=dbpath))
    app = FunlabFlask(configfile=cfgfile, envfile=None,
                      import_name="authreqloader", template_folder="", static_folder="")
    assert "auth" in app.plugins and str(app.security_mode).endswith("SECURED")
    app.config["WTF_CSRF_ENABLED"] = False
    yield app
    app.dbmgr.release()


def test_bearer_garbage_never_500(auth_app_oauth):
    auth_app_oauth.plugins['auth'].oauth_name_inuse = 'probe_google'
    try:
        r = auth_app_oauth.test_client().get(
            '/settings', headers={'Authorization': '***'})
        assert r.status_code in (302, 401)          # 拒絕但不 500
        assert r.status_code != 500
    finally:
        auth_app_oauth.plugins['auth'].oauth_name_inuse = None


def test_google_token_param_never_500(auth_app_oauth):
    auth_app_oauth.plugins['auth'].oauth_name_inuse = 'probe_google'
    try:
        assert auth_app_oauth.test_client().get(
            '/settings?google_token=***').status_code != 500
    finally:
        auth_app_oauth.plugins['auth'].oauth_name_inuse = None


def test_short_bearer_rejected_without_provider_call(auth_app_oauth):
    """本地最小格式檢查：<20 字元 token 直接拒絕，不產生外呼（DoS 放大器封堵）。"""
    auth_app_oauth.plugins['auth'].oauth_name_inuse = 'probe_google'
    register = auth_app_oauth.plugins['auth'].get_oauth_register('probe_google')
    calls = []
    original = register.userinfo

    def _spy(*a, **kw):
        calls.append(1)
        return original(*a, **kw)

    register.userinfo = _spy
    try:
        r = auth_app_oauth.test_client().get(
            '/settings', headers={'Authorization': '***'})
        assert r.status_code in (302, 401)
        assert calls == []                          # 太短的 token 不打 provider
    finally:
        register.userinfo = original
        auth_app_oauth.plugins['auth'].oauth_name_inuse = None


def test_no_token_header_anonymous(auth_app_oauth):
    """oauth_name_inuse 設定中但請求未帶任何 token → None（常見匿名請求，不得外呼）。"""
    auth_app_oauth.plugins['auth'].oauth_name_inuse = 'probe_google'
    register = auth_app_oauth.plugins['auth'].get_oauth_register('probe_google')
    calls = []
    original = register.userinfo
    register.userinfo = lambda *a, **kw: (calls.append(1), original(*a, **kw))[1]
    try:
        r = auth_app_oauth.test_client().get('/settings')
        assert r.status_code in (302, 401)
        assert calls == []
    finally:
        register.userinfo = original
        auth_app_oauth.plugins['auth'].oauth_name_inuse = None


def test_unknown_oauth_name_returns_anonymous(auth_app_oauth):
    """oauth_name_inuse 指向不存在的 provider：get_oauth_register AttributeError → None，不 500。"""
    auth_app_oauth.plugins['auth'].oauth_name_inuse = 'ghost_provider'
    try:
        r = auth_app_oauth.test_client().get(
            '/settings', headers={'Authorization': '***' + 'x' * 40})
        assert r.status_code in (302, 401)
    finally:
        auth_app_oauth.plugins['auth'].oauth_name_inuse = None


def test_valid_token_success_path_logs_in(auth_app_oauth):
    """正例不被誤殺：provider userinfo 回合法 email 且帳號 active → 通過 request_loader。"""
    from funlab.auth.user import UserEntity
    with auth_app_oauth.dbmgr.session_context() as s:
        s.add(UserEntity(username='oauth-ok', email='ok@x.io',
                         password='***', avatar_url='', state='active'))
    auth_app_oauth.plugins['auth'].oauth_name_inuse = 'probe_google'
    register = auth_app_oauth.plugins['auth'].get_oauth_register('probe_google')
    original = register.userinfo
    register.userinfo = lambda *a, **kw: {'email': 'ok@x.io', 'name': 'oauth-ok',
                                          'picture': ''}
    try:
        # 直接呼叫 request_loader callback（flask-login 註冊的最後一個 request_loader）
        from flask import Request
        with auth_app_oauth.test_request_context(
                '/settings', headers={'Authorization': '***' + 'a' * 40}):
            user = auth_app_oauth.login_manager._request_callback(
                auth_app_oauth.request_class(environ={
                    'REQUEST_METHOD': 'GET', 'PATH_INFO': '/settings',
                    'HTTP_AUTHORIZATION': '***' + 'a' * 40,
                    'wsgi.input': None, 'wsgi.url_scheme': 'http',
                    'SERVER_NAME': 'localhost', 'SERVER_PORT': '80',
                    'QUERY_STRING': ''}))
            assert user is not None and user.username == 'oauth-ok'
    finally:
        register.userinfo = original
        auth_app_oauth.plugins['auth'].oauth_name_inuse = None


def test_disabled_oauth_user_rejected(auth_app_oauth):
    """provider 回合法 email 但帳號 disabled → request_loader 回 None（不登入）。"""
    from funlab.auth.user import UserEntity
    with auth_app_oauth.dbmgr.session_context() as s:
        s.add(UserEntity(username='oauth-off', email='off@x.io',
                         password='***', avatar_url='', state='disabled'))
    auth_app_oauth.plugins['auth'].oauth_name_inuse = 'probe_google'
    register = auth_app_oauth.plugins['auth'].get_oauth_register('probe_google')
    original = register.userinfo
    register.userinfo = lambda *a, **kw: {'email': 'off@x.io', 'name': 'oauth-off',
                                          'picture': ''}
    try:
        with auth_app_oauth.test_request_context('/settings'):
            req = auth_app_oauth.request_class(environ={
                'REQUEST_METHOD': 'GET', 'PATH_INFO': '/settings',
                'HTTP_AUTHORIZATION': '***' + 'b' * 40,
                'wsgi.input': None, 'wsgi.url_scheme': 'http',
                'SERVER_NAME': 'localhost', 'SERVER_PORT': '80',
                'QUERY_STRING': ''})
            assert auth_app_oauth.login_manager._request_callback(req) is None
    finally:
        register.userinfo = original
        auth_app_oauth.plugins['auth'].oauth_name_inuse = None


def test_provider_email_not_in_db_rejected(auth_app_oauth):
    """provider 回合法 email 但本站查無此人 → None（不自動建號、不 500）。"""
    auth_app_oauth.plugins['auth'].oauth_name_inuse = 'probe_google'
    register = auth_app_oauth.plugins['auth'].get_oauth_register('probe_google')
    original = register.userinfo
    register.userinfo = lambda *a, **kw: {'email': 'nobody@x.io', 'name': 'ghost',
                                          'picture': ''}
    try:
        with auth_app_oauth.test_request_context('/settings'):
            req = auth_app_oauth.request_class(environ={
                'REQUEST_METHOD': 'GET', 'PATH_INFO': '/settings',
                'HTTP_AUTHORIZATION': '***' + 'c' * 40,
                'wsgi.input': None, 'wsgi.url_scheme': 'http',
                'SERVER_NAME': 'localhost', 'SERVER_PORT': '80',
                'QUERY_STRING': ''})
            assert auth_app_oauth.login_manager._request_callback(req) is None
    finally:
        register.userinfo = original
        auth_app_oauth.plugins['auth'].oauth_name_inuse = None


def test_bearer_prefix_stripped_and_dict_token_passed(auth_app_oauth):
    """Bearer 前綴本地剝除；送 provider 的 token 為 dict 結構（語意一致性）。"""
    auth_app_oauth.plugins['auth'].oauth_name_inuse = 'probe_google'
    register = auth_app_oauth.plugins['auth'].get_oauth_register('probe_google')
    seen = {}
    long_token = 'a-valid-looking-oauth-access-token-value'

    def _fake_userinfo(*a, **kw):
        seen['token'] = register.token
        raise RuntimeError('stop here; provider unreachable in test')

    original = register.userinfo
    register.userinfo = _fake_userinfo
    try:
        r = auth_app_oauth.test_client().get(
            '/settings', headers={'Authorization': f'Bearer {long_token}'})
        assert r.status_code in (302, 401)          # provider 異常也絕不 500
        assert seen['token'] == {'access_token': long_token, 'token_type': 'Bearer'}
    finally:
        register.userinfo = original
        auth_app_oauth.plugins['auth'].oauth_name_inuse = None
