"""
conftest.py — funlab-auth 測試前置設定
在任何測試模組 import 之前執行，確保 funlab namespace 正確解析。
"""
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# 加入 funlab-libs 路徑（funlab namespace 的主要提供者）
# ---------------------------------------------------------------------------
_WORKSPACE = Path(__file__).resolve().parents[2]
_FUNLAB_LIBS = str(_WORKSPACE / "funlab-libs")
_AUTH_ROOT = str(_WORKSPACE / "funlab-auth")

for _p in (_FUNLAB_LIBS, _AUTH_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# funlab.core._entity_registry 現為 funlab-libs 正式模組（共享 SQLAlchemy
# registry 單例）。舊版此處曾以 _RegistryStub 遮蔽該模組，令整合測試建立
# FunlabFlask 時 create_all 爆 `_RegistryStub has no attribute 'metadata'`
# → AuthView plugin 載入失敗。改為只驗證真實模組可 import，不再 stub。
# ---------------------------------------------------------------------------
import funlab.core._entity_registry as _entity_registry  # noqa: F401,E402

assert hasattr(_entity_registry.APP_ENTITIES_REGISTRY, "metadata"), \
    "APP_ENTITIES_REGISTRY 必須是真實 SQLAlchemy registry（不得被 stub 遮蔽）"
