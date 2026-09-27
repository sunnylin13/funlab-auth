from __future__ import annotations

import base64
from dataclasses import dataclass, field
from pathlib import Path

import bcrypt
from sqlalchemy import Boolean, Column, Integer, String, UniqueConstraint
# from sqlalchemy import Enum as SQLEnum
from sqlalchemy.ext.hybrid import hybrid_property
# all of application's entity, use same registry to declarate
from funlab.core._entity_registry import APP_ENTITIES_REGISTRY as entities_registry

# 本要用 enum定義role, 暫有原始資料compatible問題, 先用原本str
# class RoleEnum(enum.Enum):
#     GUEST = 'GUEST'
#     USER = 'USER'
#     MANAGER = 'MANAGER'
#     SUPERVISOR = 'SUPERVISOR'

# OAuth 帳號的佔位密碼（明文，建立時會被雜湊）；此類帳號禁止密碼登入
EXTERNAL_AUTH_PLACEHOLDER = 'account+is+from+external+authentication+provider!!!'

# check_password_login() 的回傳碼
LOGIN_OK = 'ok'
LOGIN_BAD_PASSWORD = 'bad_password'
LOGIN_EXTERNAL_ACCOUNT = 'external_account'
LOGIN_INACTIVE = 'inactive'

@dataclass
class User:
    id:int = field(init=False)
    email:str  # this what we use to login, not username
    username:str  # just a name
    password:str
    avatar_url:str
    state:str # = field(init=False)
    is_admin:bool =  field(init=False)
    # role: RoleEnum = field(init=False)
    role: str = field(init=False)
    user_folder: str = field(init=False, default=None) # user folder in the web file system

    def __post_init__(self):
        if getattr(self, 'is_admin', None) is None:
            self.is_admin = False
        if getattr(self, 'password', None) is None:
            self.password = EXTERNAL_AUTH_PLACEHOLDER
        self.hash_pass()

    def to_userentity(self, exist=False):
        user_entity = UserEntity(username=self.username, email=self.email,
                        password=self.password, avatar_url=self.avatar_url, state=self.state)
        if exist:
            user_entity.id = self.id
        user_entity.state = self.state
        user_entity.is_admin = self.is_admin
        return user_entity

    @property
    def is_active(self):
        return self.state=='active'

    @property
    def is_authenticated(self):
        return self.is_active

    @property
    def is_anonymous(self):
        return self.role.upper() == 'GUEST'

    def get_id(self):
        return str(self.id)

    # ref:https://www.vitoshacademy.com/hashing-passwords-in-python/
    def hash_pass(self):
        def is_hashed() -> bool:
            try:
                hashed = base64.b64decode(self.password.encode()).decode()
                if len(hashed) == 60 and hashed[:4] in ["$2b$", "$2a$", "$2y$"]:
                    return True
            except:
                return False
            return False
        """Hash a password for storing."""
        if not is_hashed():
            hashed = bcrypt.hashpw(self.password.encode(), bcrypt.gensalt())
            self.password = base64.b64encode(hashed).decode()
        return self.password

    def verify_pass(self, provided_password:str):
        """Verify a stored password against one provided by user"""
        if not provided_password or not self.password:
            return False
        try:
            hashed = base64.b64decode(self.password.encode())
            return bcrypt.checkpw(provided_password.encode(), hashed)
        except (ValueError, TypeError):  # 非 bcrypt 格式的舊資料一律視為不符
            return False

    def is_external_account(self) -> bool:
        """帳號是否由 OAuth 建立（密碼欄為佔位值）。"""
        return self.verify_pass(EXTERNAL_AUTH_PLACEHOLDER)

    def check_password_login(self, provided_password: str) -> str:
        """密碼登入判定，回傳 LOGIN_* 常數；只有 LOGIN_OK 可呼叫 login_user()。"""
        if self.is_external_account():
            return LOGIN_EXTERNAL_ACCOUNT
        if not self.verify_pass(provided_password):
            return LOGIN_BAD_PASSWORD
        if not self.is_active:
            return LOGIN_INACTIVE
        return LOGIN_OK

@dataclass
class OAuthUser(User):
    def __post_init__(self):
        super().__post_init__()

    @property
    def external_attrs(self):
        return ['username', 'email', 'avatar_url']

@entities_registry.mapped
@dataclass
class UserEntity(User):
    __tablename__ = 'user'
    __sa_dataclass_metadata_key__ = 'sa'

    id: int = field(init=False, metadata={'sa': Column(Integer, primary_key=True, autoincrement=True)})  # id = db.Column(GUID(), primary_key=True
    username: str = field(metadata={'sa': Column(String, nullable=False)})
    email: str = field(metadata={'sa': Column(String, nullable=False, unique=True, index=True)})
    password: str = field(metadata={'sa': Column(String, nullable=False)})
    avatar_url:str = field(metadata={'sa': Column(String)})
    state:str = field(metadata={'sa': Column(String)})
    is_admin:bool = field(init=False, metadata={'sa': Column(Boolean)})
    role: str = field(init=False, metadata={'sa': Column(String)})
    # role: RoleEnum = field(init=False, metadata={'sa': Column(SQLEnum(RoleEnum))})  # Use the Enum for the role column

    __mapper_args__ = {
        "polymorphic_identity": "user",
        "polymorphic_on": "role",
    }

    __table_args__ = (UniqueConstraint('email', name='_user_email_uc'),)

    @property
    def email_name(self):
        return self.email.split('@')[0]

    @hybrid_property
    def is_active(self):
        return self.state=='active'

    def merge_userdata(self, oauth_user:OAuthUser):
        updated=False
        for attr in vars(oauth_user):
            if attr in oauth_user.external_attrs:
                if hasattr(self, attr) and getattr(self, attr)!=getattr(oauth_user, attr):
                    setattr(self, attr, getattr(oauth_user, attr))  # user update google
                    updated=True
        return updated

