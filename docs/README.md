# funlab-auth 文件索引

2026-09-27 由 fund13-dev-arch 產出。所有論點以原始碼 + tmp sqlite 實跑驗證；引用格式 `相對路徑:符號名`。

| 檔案 | 內容 | 讀者 |
|---|---|---|
| [AUTH_GUIDE.md](AUTH_GUIDE.md) | 現行架構與使用說明：AuthView 如何被 plugin manager 視為 security provider、LoginManager 接線、UserEntity single-table inheritance 與 `load_user(classes=...)`、OAuth 設定鍵語意、全路由表、`check_password_login` 回傳語意、user_folder 規則、session/cookie 鍵、部署須知 | 想理解/使用本 plugin 的人 |
| [IMPROVEMENT_PLAN.md](IMPROVEMENT_PLAN.md) | 改善方案 AUTH-01…AUTH-14：每項含問題與影響、優先級、目標檔/函式、完整修正程式碼、完整 pytest、驗證指令、風險與禁止事項；附實施順序與 PR 切分、實證輸出摘要、無法核實事項 | fund13-dev-coder（實作者） |
| [snippets/test_auth_routes.py](snippets/test_auth_routes.py) | 已修復項（H2 /login 密碼驗證、H3 /resetpass 加權）之防回歸整合測試；目標位置 `tests/integration/test_auth_routes.py`；實跑 **15 passed** | coder |
| [snippets/test_auth_defects.py](snippets/test_auth_defects.py) | 未修缺陷之重現測試（斷言現行錯誤行為）；修復對應 AUTH-## 後該項測試轉 FAIL 屬預期，按各項 (e) 反轉後併入防回歸集；實跑 **14 passed** | coder |

## 快速狀態

- 測試基線：`cd funlab-auth && source ~/workspaces/fund13/.venv/bin/activate && python -m pytest -q` → 19 passed。
- 已修復（working tree，未 commit）：H2 /login 驗證密碼＋rememberme、H3 /resetpass 僅限本人＋拒 OAuth＋成功即登出。
- 待修（依優先級）：**P0** AUTH-01（刪帳號舊 cookie→全站 500）、AUTH-03（[AuthView] 標量鍵→整站 fail-open 降 PUBLIC）；**P1** AUTH-02（開放註冊）、AUTH-04（request_loader Bearer 分支 500）、AUTH-05（無登入限流）、AUTH-07（GET logout）、AUTH-10（load_user 裸 except）；**P2** AUTH-06/08/09/11/12/13/14。
