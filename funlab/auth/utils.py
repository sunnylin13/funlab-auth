from typing import Type
from sqlalchemy.orm import Session, with_polymorphic
from sqlalchemy import select, or_
from funlab.core.appbase import app_cache
from .user import UserEntity

# @app_cache.memoize() # 有AttributeError: Can't pickle local object 'SolClient.__init__.<locals>.<lambda>', 所以不能cache
def load_user(id_email, sa_session:Session, classes='*')->Type[UserEntity]:
    """load任何使用sqlalchemy "Mapping Class Inheritance Hierarchies"採用single table inheritance定義UserEntity的subclass,
    用id或email查詢在不同role資料下得到對應正確的UserEntity或其subclass instance
        例如以下定義GuestEntity, 它的role 欄位資料即是'guest', 返回的就是GuestEntity instance
        @entities_registry.mapped
        @dataclass
        class GuestEntity(UserEntity):
            __mapper_args__ = {
                "polymorphic_identity": "guest",
            }
    Args:
        id_email ([type]): [description]
        sa_session ([type]): [description]
    """
    User: UserEntity = with_polymorphic(UserEntity, classes=classes)
    try:
        id = int(id_email)
        stmt = select(User).where(User.id == id)
    except:
        stmt = select(User).where(User.email == id_email)
    user = sa_session.execute(stmt).scalar()
    return user

def save_user(user:Type[UserEntity], sa_session:Session):  # Type[UserEntity] means user should be an instance of UserEntity or any of its subclasses
    sa_session.merge(user)
    sa_session.commit()

