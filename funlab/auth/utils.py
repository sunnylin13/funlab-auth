import importlib
import threading
from typing import Type
from sqlalchemy.orm import Session, with_polymorphic
from sqlalchemy import select, or_
from funlab.core.appbase import app_cache
from .user import UserEntity
import logging
from funlab.utils import log

# State for async preload control
_polymorphic_preload_started = False
_polymorphic_preload_lock = threading.Lock()

# Ensure the actual preload operation runs only once (thread-safe)
_polymorphic_load_lock = threading.Lock()
_polymorphic_loaded = False

# single logger used by this module
mylogger = log.get_logger(__name__, level=logging.INFO)

def _ensure_user_polymorphic_mappers_loaded():
    """Load known STI subclasses so SQLAlchemy can resolve role polymorphic identities.

    In this workspace, roles like ``manager`` / ``supervisor`` are declared in
    ``finfun.core.entity.manager``. If that module wasn't imported yet, querying
    UserEntity rows with role='supervisor' raises:
    "No such polymorphic_identity 'supervisor' is defined".
    """
    global _polymorphic_loaded
    with _polymorphic_load_lock:
        if _polymorphic_loaded:
            return
        try:
            import time
            start = time.perf_counter()
            mylogger.info("Preloading user polymorphic mappers...")
            # importlib.import_module('finfun.core.entity.manager')
            import finfun.core.entity.manager
            elapsed = time.perf_counter() - start
            mylogger.info(f"Preloading user polymorphic mappers took {elapsed:.2f}s.")
            _polymorphic_loaded = True
        except Exception:
            # Keep auth usable even when finfun-core is not installed/available.
            mylogger.exception("Failed to preload user polymorphic mappers")

def preload_user_polymorphic_mappers_async():
    """Preload STI subclasses in background to avoid first-login latency."""
    global _polymorphic_preload_started
    with _polymorphic_preload_lock:
        if _polymorphic_preload_started:
            return
        _polymorphic_preload_started = True

    def _worker():
        _ensure_user_polymorphic_mappers_loaded()

    threading.Thread(
        target=_worker,
        name='auth-user-polymorphic-preload',
        daemon=True,
    ).start()

# @app_cache.memoize() # 有AttributeError: Can't pickle local object 'SolClient.__init__.<locals>.<lambda>', 所以不能cache
def load_user(id_email, sa_session:Session, classes='*')->Type[UserEntity]|None:
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
    _ensure_user_polymorphic_mappers_loaded()
    if classes == '*':
        User = UserEntity
    else:
        User = with_polymorphic(UserEntity, classes=classes)
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

