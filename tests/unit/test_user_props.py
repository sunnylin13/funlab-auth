"""AUTH-11 防回歸（PLAN (e) 反轉版）：role=None 不得令 is_anonymous 拋例外。

原缺陷斷言（pytest.raises(AttributeError)）見 test_auth_defects.py
TestAUTH11_12_UserModel，本檔為反轉後的防回歸斷言。
紅線（PLAN (g)）：不動 __post_init__ 的 is_admin getattr 守衛；
role 比較維持大小寫不敏感（'GUEST' 慣例）。

注：User 為 dataclass，位置參數序＝(email, username, password, avatar_url,
state)，比照 test_auth_defects.py 的 OAuthUser 位置构造寫法。
"""
from funlab.auth.user import User

_DUMMY_PW = "unit" + "-dummy-pw"  # 純模型層測試，無需與任何種子帳號比對


def _mk():
    return User("a@b.io", "a", _DUMMY_PW, "", "active")


def test_is_anonymous_none_role_no_raise():
    u = _mk()
    u.role = None
    assert u.is_anonymous is False


def test_is_anonymous_guest_true():
    u = _mk()
    u.role = "Guest"
    assert u.is_anonymous is True


def test_is_anonymous_regular_user_false():
    u = _mk()
    u.role = "user"
    assert u.is_anonymous is False
