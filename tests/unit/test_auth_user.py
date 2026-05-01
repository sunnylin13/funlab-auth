"""
T-auth-002 — funlab-auth User 密碼雜湊單元測試
涵蓋：hash_pass、verify_pass、OAuthUser 預設密碼

注意：sys.path 與模組 stub 設定由 tests/conftest.py 完成。
"""
from funlab.auth.user import User, OAuthUser


class TestHashPass:
    """測試 User.hash_pass() 行為"""

    def test_password_hashed_on_init(self):
        """建立 User 後，密碼應以 base64(bcrypt) 格式儲存"""
        import base64
        user = User(email="a@b.com", username="a", password="plain123",
                    avatar_url="", state="active")
        decoded = base64.b64decode(user.password.encode()).decode()
        assert decoded[:4] in ("$2b$", "$2a$", "$2y$"), "密碼應為 bcrypt 格式"

    def test_already_hashed_not_double_hashed(self):
        """已雜湊的密碼不應被重複雜湊"""
        user = User(email="a@b.com", username="a", password="plain123",
                    avatar_url="", state="active")
        hashed_once = user.password
        # 再次呼叫 hash_pass 不應改變密碼
        result = user.hash_pass()
        assert result == hashed_once

    def test_hash_is_different_per_call(self):
        """相同明文，兩次雜湊應產生不同鹽值結果"""
        u1 = User(email="a@b.com", username="a", password="same_pass",
                  avatar_url="", state="active")
        u2 = User(email="b@b.com", username="b", password="same_pass",
                  avatar_url="", state="active")
        assert u1.password != u2.password, "bcrypt 每次應產生不同鹽值"


class TestVerifyPass:
    """測試 User.verify_pass() 行為"""

    def test_correct_password_returns_true(self):
        """正確密碼應驗證通過"""
        user = User(email="a@b.com", username="a", password="correct_pass",
                    avatar_url="", state="active")
        assert user.verify_pass("correct_pass") is True

    def test_wrong_password_returns_false(self):
        """錯誤密碼應驗證失敗"""
        user = User(email="a@b.com", username="a", password="correct_pass",
                    avatar_url="", state="active")
        assert user.verify_pass("wrong_pass") is False

    def test_empty_password_does_not_raise(self):
        """空字串密碼驗證不應拋出例外，應回傳 False"""
        user = User(email="a@b.com", username="a", password="real_pass",
                    avatar_url="", state="active")
        assert user.verify_pass("") is False

    def test_unicode_password(self):
        """Unicode 密碼（含中文/特殊字元）應正確雜湊與驗證"""
        pwd = "密碼123!@#"
        user = User(email="a@b.com", username="a", password=pwd,
                    avatar_url="", state="active")
        assert user.verify_pass(pwd) is True
        assert user.verify_pass(pwd + "x") is False


class TestOAuthUser:
    """測試 OAuthUser 的預設密碼行為"""

    def test_oauth_user_has_default_password(self):
        """OAuthUser 不傳入 password，應設定為佔位符字串"""
        user = OAuthUser(email="oauth@example.com", username="oauth_user",
                         password=None, avatar_url="", state="active")
        # 佔位符字串的 bcrypt 雜湊應可正常儲存
        assert user.password is not None
        assert len(user.password) > 0

    def test_oauth_user_placeholder_not_verifiable_by_blank(self):
        """OAuthUser 佔位符密碼不應被空字串驗證通過"""
        user = OAuthUser(email="oauth@example.com", username="oauth_user",
                         password=None, avatar_url="", state="active")
        assert user.verify_pass("") is False


class TestUserProperties:
    """測試 User 屬性方法"""

    def test_is_active_when_state_is_active(self):
        user = User(email="a@b.com", username="a", password="p",
                    avatar_url="", state="active")
        assert user.is_active is True

    def test_is_not_active_when_state_is_other(self):
        user = User(email="a@b.com", username="a", password="p",
                    avatar_url="", state="inactive")
        assert user.is_active is False

    def test_is_authenticated_follows_is_active(self):
        user = User(email="a@b.com", username="a", password="p",
                    avatar_url="", state="active")
        assert user.is_authenticated is True
