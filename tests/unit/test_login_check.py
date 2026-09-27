"""
funlab-auth 密碼登入判定單元測試（User.check_password_login）
防回歸：/login 曾在 email 存在時未驗證密碼即 login_user。
"""
from funlab.auth.user import (LOGIN_BAD_PASSWORD, LOGIN_EXTERNAL_ACCOUNT,
                              LOGIN_INACTIVE, LOGIN_OK, OAuthUser, User)


def _user(password="RightPass!1", state="active"):
    return User(email="a@b.com", username="a", password=password,
                avatar_url="", state=state)


class TestCheckPasswordLogin:
    def test_correct_password_ok(self):
        assert _user().check_password_login("RightPass!1") == LOGIN_OK

    def test_wrong_password_rejected(self):
        assert _user().check_password_login("WRONG") == LOGIN_BAD_PASSWORD

    def test_empty_password_rejected(self):
        assert _user().check_password_login("") == LOGIN_BAD_PASSWORD
        assert _user().check_password_login(None) == LOGIN_BAD_PASSWORD

    def test_inactive_user_rejected_even_with_correct_password(self):
        u = _user(state="disabled")
        assert u.check_password_login("RightPass!1") == LOGIN_INACTIVE

    def test_inactive_user_wrong_password_reports_bad_password(self):
        # 密碼錯誤時不得洩漏帳號狀態
        u = _user(state="disabled")
        assert u.check_password_login("WRONG") == LOGIN_BAD_PASSWORD

    def test_oauth_account_cannot_password_login(self):
        u = OAuthUser(email="g@x.io", username="g", password=None,
                      avatar_url="", state="active")
        assert u.check_password_login("anything") == LOGIN_EXTERNAL_ACCOUNT
        # 即使攻擊者知道佔位字串也不能登入
        assert u.check_password_login(
            "account+is+from+external+authentication+provider!!!") == LOGIN_EXTERNAL_ACCOUNT

    def test_non_bcrypt_legacy_password_rejected_not_raise(self):
        u = _user()
        u.password = "not-a-bcrypt-hash"
        assert u.verify_pass("not-a-bcrypt-hash") is False
        assert u.check_password_login("not-a-bcrypt-hash") == LOGIN_BAD_PASSWORD
