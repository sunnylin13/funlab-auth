"""AUTH-01 防回歸：user_loader / request_loader 對「使用者已刪除」必須回 None，
讓 flask-login 走匿名 + unauthorized 流程（導向登入頁），絕不可拋例外造成全站 500。

對應 IMPROVEMENT_PLAN AUTH-01 (e)。修復前本檔 FAIL（RED）＝缺陷重現；
修復後 PASS。
執行：cd funlab-auth && python -m pytest -q tests/integration/test_auth_loaders.py
"""
import pytest

pytestmark = pytest.mark.integration


def test_user_loader_missing_user_returns_none(auth_app):
    assert auth_app.login_manager._user_callback("99999") is None


def test_deleted_user_cookie_anonymous_not_500(auth_app):
    c = auth_app.test_client()
    with c.session_transaction() as sess:
        sess["_user_id"] = "99999"
        sess["_fresh"] = True
    r = c.get("/settings")
    assert r.status_code in (200, 302)      # 匿名處理（導向登入），絕不 500
    assert r.status_code != 500


def test_deleted_user_cookie_redirect_lands_login_200(auth_app):
    """卡指定斷言：已刪除使用者持舊 session 訪受保護頁 → 最終導向登入頁 200，非 500。"""
    c = auth_app.test_client()
    with c.session_transaction() as sess:
        sess["_user_id"] = "99999"
        sess["_fresh"] = True
    r = c.get("/settings", follow_redirects=True)
    assert r.status_code == 200
    assert b"/login" in r.request.url.encode() or "login" in r.request.path


def test_request_loader_stale_user_id_not_500(auth_app):
    c = auth_app.test_client()
    with c.session_transaction() as sess:
        sess["user_id"] = "99999"
    assert c.get("/settings").status_code != 500
