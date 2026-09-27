# funlab-auth 使用與架構指南（AUTH_GUIDE）

> 2026-09-27，fund13-dev-arch。描述**現況**（working tree 含 /login 密碼驗證與 /resetpass 加權）。
> 引用格式 `相對路徑:符號名`（約 Lxx）。缺陷與改進見 `IMPROVEMENT_PLAN.md`；本檔只描述現行行為。

## 1. 這是何物

funlab-auth 是 funlab-flaskr 的認證 plugin（entry point `AuthView = funlab.auth.view:AuthView`，`pyproject.toml:[project.entry-points]`），提供：

- 帳號密碼登入（bcrypt，`funlab/auth/user.py:User.hash_pass/verify_pass`）
- OAuth2/OIDC 登入（authlib，可配多個 provider，Google/GitLab 範例見 `funlab/auth/conf/plugin.toml`）
- flask-login 整合（LoginManager、user_loader/request_loader）
- /login /logout /register /resetpass /settings 路由與 Tabler 模板

套件依賴：authlib、bcrypt、flask-wtf、funlab-flaskr（pyproject dependencies）。

## 2. 如何被当作 security provider 載入

1. **中繼資料**：`pyproject.toml:[tool.funlab_plugin_metadata.AuthView]` 宣告 `load_mode="startup"`、`provides_security=true`；funlab-libs `plugin_manager` 啟動時經 entry point group `funlab_plugin` 發現並實例化（實測啟動後 `app.plugins` 含 `auth`）。
2. **協議偵測**：`funlab-libs/funlab/core/plugin.py:ISecurityProvider` 是 runtime-checkable Protocol——只看有沒有 `login_manager` property（duck typing）。`view.py:AuthView.login_manager`（約 L131-139）滿足它。
3. **接線**：`plugin_manager.py`（約 L825-848）對符合協議的 plugin：把 `self.app.login_manager` 換成 plugin 的、`init_app()`、`security_mode=SECURED`、`authorization_enabled=True`、記錄 `security_provider_name='AuthView'`；第二個 security provider 只會 warning 不覆蓋。
4. **LoginManager 歸屬**：`appbase.py:register_plugins`（約 L459-468）先建「佔位」LoginManager（login_view=`root_bp.blank`、匿名 user_loader、`_default_user_loader=True` 旗標）。`AuthView.__init__`（約 L34-41）**重用** app 上既有 LoginManager（否則自建+init_app），設定 `login_view='auth_bp.login'`，註冊自有 `user_loader` 後 `delattr(login_manager, '_default_user_loader')`（約 L61-62）清掉佔位旗標。
5. plugin 掛點：`AuthView._perform_health_check`（約 L102-107）供 plugin manager 健康檢查；`setup_menus`（約 L109-127）在使用者選單塞 Settings 與 Logout。

## 3. 使用者模型（user.py）

- **User（dataclass 基類）**：欄位 `id/email/username/password/avatar_url/state/is_admin/role/user_folder`。`__post_init__`（約 L43-48）：`is_admin None→False`；`password None→EXTERNAL_AUTH_PLACEHOLDER`（佔位明文常數，約 L22）並立刻 `hash_pass()`。
- **hash_pass**：bcrypt 雜湊後再 **base64** 存入 `password` 字串欄；已雜湊（b64 解出 `$2b$/$2a$/$2y$` 開頭、長 60）不重雜。
- **UserEntity（SQLAlchemy 映射）**：表 `user`，email unique+index；**single table inheritance**：`polymorphic_on='role'`、`polymorphic_identity='user'`（約 L139-142）。任何 plugin/app 可再派生子類（例：`polymorphic_identity='guest'` → role='guest'），同表不同 role 值。`funlab/core/_entity_registry.py:APP_ENTITIES_REGISTRY` 全應用共用 registry；`AuthView.entities_registry` property 讓 plugin manager `create_registry_tables()` 建表。
- **is_active**=`state=='active'`（hybrid_property，可在 SQL 用）；**is_authenticated** 跟隨 is_active；**is_anonymous**=`role.upper()=='GUEST'`（role=None 會 raise——見 AUTH-11）；**get_id**=str(id)。
- **OAuthUser**：僅多一組 `external_attrs=['username','email','avatar_url']`；`UserEntity.merge_userdata(oauth_user)`（約 L154-161）只把這三個欄位從 provider userinfo 覆蓋進既有帳號（user 在 Google 改名/換頭像→下次 OAuth 登入自動同步）。
- **to_userentity()**：把（可能未映射的）User/OAuthUser 轉成可入庫 UserEntity（含 id/state/is_admin）。

### check_password_login 回傳語意（約 L104-112）

`User.check_password_login(provided_password) -> str`，判定順序：

| 條件 | 回傳 | 呼叫端語意 |
|---|---|---|
| `is_external_account()`（密碼欄 verify 得到佔位明文） | `LOGIN_EXTERNAL_ACCOUNT` | 不可密碼登入，導向 provider |
| `verify_pass` 失敗（含空/None/非 bcrypt 舊資料） | `LOGIN_BAD_PASSWORD` | 顯示帳密錯誤 |
| `not is_active` | `LOGIN_INACTIVE` | 停用，聯絡管理員 |
| 全部通過 | `LOGIN_OK` | **只有此值**可 `login_user()` |

注意：external 判定在密碼比對**之前**，所以 OAuth 帳號連「密碼對錯」都不揭露（先回 external）。`is_external_account` 的實作是「佔位明文 bcrypt verify 成功」——密碼內容探測，勿改佔位字串值（IMPROVEMENT_PLAN AUTH-12）。

### load_user(classes=...)（utils.py:load_user）

`load_user(id_email, sa_session, classes='*')`：`int(id_email)` 成功→按 id 查；失敗（TypeError/ValueError，經裸 except——見 AUTH-10）→按 email 查。`classes='*'` 用 UserEntity（polymorphic 自動依 role 實例化對應子類）；傳 SQLAlchemy 子類集合時走 `with_polymorphic(UserEntity, classes=...)`。回傳 `None` 表示查無。
`save_user(user, session)`＝`merge+commit`。

### user_folder 規則

`FunlabFlask.get_user_data_storage_path(username)`（funlab-flaskr app.py:90-94）：`<套件 root_path>/_users/<username 轉小寫、去空格>/`，**存取時即時 mkdir**。auth 側在所有登入/load 路徑（login、authorize、register、user_loader、request_loader）都重設 `user.user_folder` —— user_folder 是 **runtime 屬性，非 DB 欄位**；下游（finfun-fundmgr 憑證/交易檔案）直接用它。`_users/` 嚴禁在任何 static 路由下（H1 已處裡）。

## 4. 設定鍵（conf/plugin.toml 與 finfun/config.toml）

來源優先序：plugin 內建 `funlab/auth/conf/plugin.toml` → 被 app 設定檔 `[AuthView]` section 覆蓋（`Plugin._init_configuration` 以類別名義為 section，`funlab-libs/funlab/core/__init__.py:_Configuable.get_config`）。密鑰一律用 `"{{ENV_VAR:NAME}}"` 佔位由環境檔注入，**勿把密鑰值寫進任何 toml**。

`[AuthView]` 語意：

- **每個子 section = 一個 OAuth provider**，section 名自訂（如 `funlab_google`）。view.py 對所有鍵 `.pop('provider')`（約 L50）——**目前不可在 [AuthView] 直放標量鍵**（會炸 AuthView，AUTH-03）。
- 專屬鍵（先 pop 再傳 authlib）：
  - `provider`：顯示用名稱（選單按鈕文字、oauths_info）
  - `userinfo_key_mapping`：`{ username='...', avatar_url='...' }` 覆寫預設 `{email:'email', username:'username', avatar_url:'avatar_url'}`（view.py:46-52）——provider 回傳欄位名不同時用（Google 需 `username='name', avatar_url='picture'`）。
- 其餘鍵原樣進 `oauth.register()`（authlib）：`client_id`、`client_secret`、`authorize_url`、`access_token_url`、`jwks_uri`、`userinfo_endpoint`、`api_base_url`、`client_kwargs={scope=...}`。缺 `userinfo_endpoint` 時構造不報錯、首次 userinfo() 才爆（E4）。
- `HOOK_EXAMPLES = true`（約 L63）：註冊 debug hook 範例；**在修復 AUTH-03 前不可開啟**。
- `ALLOW_REGISTER`：**尚未實作**（AUTH-02 提案鍵，修復後預設 false）。

## 5. 路由一覽（blueprint `auth_bp`，url_prefix=""→根路徑）

| 路徑 | 方法 | 需登入 | 行為（現況） |
|---|---|---|---|
| `/login`、`/login/`、`/login/<style>` | GET/POST | 否 | POST（含 `login` 欄位）：查使用者→`check_password_login`→OK 才 `login_user(remember=request.form.get('rememberme')=='y')`→302 /home；各失敗態 flash 渲染 sign-in。GET 已登入→302 /home；匿名→渲染 sign-in[-style].html（style 變體模板：cover/illustration） |
| `/oauth_login/<oauth_name>` | GET | 否 | 產生 provider 跳轉（authlib 自動寫 state 進 session）；記 `_oauth_login_start` 時間戳 |
| `/authorize/<oauth_name>` | GET | 否 | provider callback：`authorize_access_token()`（authlib 驗 state）→ `userinfo()` → 依 email `load_user`：有則 `merge_userdata`+存，無則 `OAuthUser(...).to_userentity()` 入庫 → `session['oauth_token']=token` → `login_user(user)` → 302 /home。token 為 None/例外→flash+sign-in（細節洩漏見 AUTH-14） |
| `/logout` | GET | 是 | `logout_user()`+清 `oauth_token`/`user_id` → 302 index。GET 無 CSRF（AUTH-07） |
| `/register` | GET/POST | 否 | 建 `state='active'` UserEntity（無開關、未跑表單驗證——AUTH-02） |
| `/resetpass` | GET/POST | 是（@login_required） | 僅能改 current_user 自己：email 須相符→新密兩欄一致→舊密 `check_password_login`（EXTERNAL 拒、非 OK 拒）→ `password=new; hash_pass(); save_user` → `logout_user()` + 渲染 sign-in（H3 現況） |
| `/settings` | GET | 是 | 渲染 settings.html（内容由其他 plugin 填） |

CSRF：funlab-flaskr 全域 `CSRFProtect`（ADR-016）對以上所有 POST 強制；模板都帶 `form.hidden_tag()`（缺 flash 的 UI 問題見 AUTH-13；GET /logout 不在覆蓋範圍）。

## 6. session / cookie 中的鍵

| 鍵 | 寫入者 | 語意 |
|---|---|---|
| `_user_id`、`_fresh`、`_id`、（remember 時）`_remember` | flask-login `login_user` | session cookie 簽名內；`_id` 供 flask-login session-protection（預設 level=None→未啟用綁定） |
| `user_id`（**無底線**） | 外部 API 流程/插件（如 fundmgr qa harness） | request_loader 第一優先分支：session 內有此鍵→按 id load |
| `oauth_token` | authorize | provider token dict（洩漏面見 AUTH-14；logout 清除） |
| `_oauth_login_start` | oauth_login | debug 時間戳 |

flask_login 的 request_loader 只在「有 session cookie、無 `_user_id`」或带 Authorization 頭時觸發；Authorization/`?google_token=` 分支把裸字串交給 provider `userinfo()` 複驗（現況會把非 dict 字串塞 token、失敗 raise→500，見 AUTH-04）。token 暫存於 `flask.g`（authlib flask_client 行為）——無跨請求殘留。

unauthorized 行為（`register_login_handler.unauthorized_handler`）：JSON/API 請求→401 `{'error':'authentication_required'}`；一般→302 `/login/?next=<絕對URL>`（next 現況未被跟隨，AUTH-09）。

## 7. 部署須知

- 需要 `SECRET_KEY` 固定值（funlab-flaskr 未 pin 會隨機、重啟後 session/CSRF 全失效並 warn）。
- 目前單程序執行（systemd fund13-web）；記憶體型狀態（AUTH-05 提案限流）與 `oauth_name_inuse` 執行緒全域皆單程序假設。
- 移除使用者後，舊 cookie 現況會 500（AUTH-01 修復前勿依賴刪帳號）。
- 註冊入口公網暴露中（AUTH-02）；公網部署前務必處理。
- 版本相容：python≥3.12、authlib 1.6.x、flask-login 0.6.3 行為（`login_user` 對 inactive 回 False、不raise）。

## 8. 測試

- 單元（不需完整 app）：`tests/conftest.py` stub `funlab.core._entity_registry` 與 sys.path；`tests/unit/test_auth_user.py`（hash/verify/OAuthUser/properties）、`tests/unit/test_login_check.py`（check_password_login 四態）。基線 `python -m pytest -q`＝**19 passed**。
- 整合（tmp sqlite FunlabFlask）：見 `docs/IMPROVEMENT_PLAN.md` §0 fixture 與 `docs/snippets/`（防回歸 15 passed／缺陷重現 14 passed）。
