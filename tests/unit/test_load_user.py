"""AUTH-10 防回歸（PLAN AUTH-10 (e)）：utils.load_user 不再裸 except。

只接 (TypeError, ValueError)；非整數輸入（email/None/亂字串）走 email 查詢，
真正的 DB 異常必須上拋，不得誤判為「查無此人」。
in-memory sqlite 直接建表，不需完整 app（沿用 tests/conftest.py 之 registry 前置）。
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(element, compiler, **kw):  # pragma: no cover
    return "JSON"


from funlab.auth.user import UserEntity, entities_registry  # noqa: E402
from funlab.auth.utils import load_user  # noqa: E402


@pytest.fixture()
def sa_session():
    eng = create_engine("sqlite:///:memory:")
    entities_registry.metadata.create_all(eng)
    with Session(eng) as s:
        s.add(UserEntity(username='a', email='a@b.io', password='***',
                         avatar_url='', state='active'))
        s.commit()
        yield s


def test_load_by_email_and_id(sa_session):
    assert load_user('a@b.io', sa_session).username == 'a'
    assert load_user(str(load_user('a@b.io', sa_session).id), sa_session).email == 'a@b.io'


def test_none_returns_none(sa_session):
    assert load_user(None, sa_session) is None


def test_garbage_string_treated_as_email_query(sa_session):
    """亂字串走 email 查詢 → 查無回 None（語意與現況一致，非吞錯）。"""
    assert load_user('not-an-email', sa_session) is None


def test_db_error_propagates(sa_session):
    """底層故障（表不存在→OperationalError）必須上拋、不得誤判查無此人。

    註：PLAN (e) 原版以 sa_session.close() 模擬故障，但 SQLAlchemy 2.x 的
    Session close 後可自動重開交易、不會拋錯，故改以 drop_all 製造真實 DB 異常。
    """
    from sqlalchemy.exc import SQLAlchemyError
    entities_registry.metadata.drop_all(sa_session.get_bind())
    with pytest.raises(SQLAlchemyError):
        load_user('a@b.io', sa_session)
