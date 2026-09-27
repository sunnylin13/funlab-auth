"""
conftest.py — funlab-auth 測試前置設定
在任何測試模組 import 之前執行，確保 funlab namespace 正確解析。
"""
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

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
# stub funlab.core._entity_registry（僅當 funlab-libs 版本缺此模組時）
# 真模組可用時一律優先：stub 無 metadata 等介面，會使整合測試的
# FunlabFlask create_all 崩潰（dbmgr 需要 registry.metadata）。
# ---------------------------------------------------------------------------
if "funlab.core._entity_registry" not in sys.modules:
    try:
        import funlab.core._entity_registry  # noqa: F401
    except ImportError:
        class _RegistryStub:
            """模擬 APP_ENTITIES_REGISTRY，讓 @mapped 裝飾器直接回傳 cls。"""
            def mapped(self, cls):
                return cls

        _entity_registry_mod = types.ModuleType("funlab.core._entity_registry")
        _entity_registry_mod.APP_ENTITIES_REGISTRY = _RegistryStub()
        sys.modules["funlab.core._entity_registry"] = _entity_registry_mod
