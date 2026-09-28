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
# 以本檔位置為基準，主倉與 git worktree（<ws>/funlab-auth/.worktrees/<t>）皆可正確解析
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parents[1]  # tests/ 上一層＝本倉根（含 worktree）
_AUTH_ROOT = str(_HERE)
for _ws in (_HERE.parents[1], _HERE.parents[3]):  # 主倉: parents[1]=workspace；worktree: parents[3]=workspace
    _cand = _ws / "funlab-libs"
    if _cand.is_dir():
        break
_FUNLAB_LIBS = str(_cand)

for _p in (_FUNLAB_LIBS, _AUTH_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# funlab.core._entity_registry 現為 funlab-libs 正式模組（共享 SQLAlchemy
# registry 單例）。整合測試建立 FunlabFlask 時 create_all 需要真實 registry
# 的 metadata；舊版此處無條件以 _RegistryStub 遮蔽，令 AuthView plugin
# 載入失敗（'_RegistryStub' has no attribute 'metadata'）。
# R1（t_ef7712fa）合併 WP-0b×A6-1×A4 語意聯集：一律優先真實模組並斷言
# metadata 存在（WP-0b 防遮蔽保險絲）；僅當 funlab-libs 版本缺此模組時
# fallback 到 stub 並註冊 sys.modules（A6-1/A4 相容性）。
# ---------------------------------------------------------------------------
try:
    import funlab.core._entity_registry as _entity_registry  # noqa: F401,E402
    assert hasattr(_entity_registry.APP_ENTITIES_REGISTRY, "metadata"), \
        "APP_ENTITIES_REGISTRY 必須是真實 SQLAlchemy registry（不得被 stub 遮蔽）"
except ImportError:
    class _RegistryStub:
        """模擬 APP_ENTITIES_REGISTRY，讓 @mapped 裝飾器直接回傳 cls。"""
        def mapped(self, cls):
            return cls

    _entity_registry = types.ModuleType("funlab.core._entity_registry")
    _entity_registry.APP_ENTITIES_REGISTRY = _RegistryStub()
    sys.modules["funlab.core._entity_registry"] = _entity_registry
