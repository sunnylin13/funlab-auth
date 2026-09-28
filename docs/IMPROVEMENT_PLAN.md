# funlab-auth 改善方案（IMPROVEMENT_PLAN）

> 產出者：fund13-dev-arch（2026-09-27）。讀者：fund13-dev-coder。
> 所有主張均先讀原始碼核實，並以 tmp sqlite + Flask test_client 實跑驗證（探針輸出見附錄 C）。
> 引用格式：`相對路徑:符號名`（約 Lxx 為行文時行號，可能有 ±2 漂移）。
> **現況基線**：H2（/login 密碼驗證）與 H3（/resetpass 加權）熱修已入庫（commit 614f891）。本檔不重複修歷史，只處理未修項。
> **實施狀態（2026-09-28 對帳）**：AUTH-01/03（A4/A6-1 PR#2/#3）、AUTH-04/07/10＋Q3/Q4 裁示項 AUTH-02/05（B3 commit fd8d068：ALLOW_REGISTER 預設 false＋邀請制、/login per-IP＋per-email 內存限流）、AUTH-06/08/09/11/12/13/14（C3 commit 27d7967，含 role NOT NULL 遷移 c9a4e6b8d3f1 已上正式庫）。已部署正式服務。測試基線現況 unit **26 passed**（docs/snippets defects 檔為設計性重現腳本，不計入門控）。本文 (a) 段描述【修復前】缺陷。

## 0. 環境與測試基礎（所有條目共用）

- 執行環境：`cd funlab-auth && source ~/.venv/fund13/bin/activate`（套件由 venv editable 安裝，`funlab.auth` 可直接 import；完整 app 測試需在任一目錄執行均可，但入口探針慣例在 `finfun/` 下跑）。
- 現有測試基線：`python -m pytest -q` → **19 passed**（任何修改後必須 ≥19 且零失敗）。
- 整合測試需要完整 `FunlabFlask`（tmp sqlite）。兩個關鍵前提：
  1. **JSONB→sqlite shim**：finfun 實體使用 PostgreSQL `JSONB`，建表前必須註冊 `@compiles(JSONB, "sqlite")`，否則 `create_all` 爆錯。
  2. **測試表單層 CSRF 關閉**（`app.config['WTF_CSRF_ENABLED']=False`）；全域 CSRFProtect 行為由 funlab-flaskr 的 `tests/test_csrf_protection.py` 守護，funlab-auth 測試不重複測。
- 共用 fixture（下方所有測試代碼中的 `auth_app` 皆指此 fixture；完整檔見附錄 A）：

```python
# tests/integration/conftest.py（新增）
import os, tempfile
from pathlib import Path
import pytest
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles

@compiles(JSONB, "sqlite")
def _jsonb_sqlite(element, compiler, **kw):
    return "JSON"

os.environ.setdefault("QT_API", "None")
os.environ.setdefault("MPLBACKEND", "Agg")

CFG_TEMPLATE = """
[FunlabFlask]
APP_NAME='authtest'
SECRET_KEY='authtest-secret'
PREWARM_ENABLED=false
HOME_ENTRY='blank.html'
ENV = '{{{{ENV.T}}}}'
[ENV]
  [ENV.T]
  TESTING = true
  WSGI = 'flask'
  PORT = 5995
  DATABASE = '{{{{DATABASE.T}}}}'
[DATABASE]
  [DATABASE.T]
  url = 'sqlite:///{dbpath}'
[CACHE]
CACHE_TYPE='SimpleCache'
"""

@pytest.fixture(scope="module")
def auth_app():
    from funlab.flaskr.app import FunlabFlask
    dbpath = tempfile.mktemp(suffix=".db", dir=os.environ.get("TMPDIR"))
    cfgfile = tempfile.mktemp(suffix=".toml", dir=os.environ.get("TMPDIR"))
    Path(cfgfile).write_text(CFG_TEMPLATE.format(dbpath=dbpath))
    app = FunlabFlask(configfile=cfgfile, envfile=None,
                      import_name="authtest", template_folder="", static_folder="")
    assert "auth" in app.plugins and str(app.security_mode).endswith("SECURED")
    app.config["WTF_CSRF_ENABLED"] = False
    yield app
    app.dbmgr.release()
```

- **既有防回歸**（已完成，見附錄 A `test_auth_routes.py`，實跑 **15 passed**）：/login 錯誤密碼、無 rememberme、OAuth 佔位密碼、inactive、/resetpass 匿名/改他人/OAuth/錯舊密碼/確認不符/成功流程+登出。
- **缺陷重現檔**（附錄 B `test_auth_defects.py`，實跑 **14 passed**）：斷言「現行錯誤行為」，修復對應項後該測試會 FAIL，屆時按該項 (e) 的反轉版更新。

---

## AUTH-01（P0）user_loader / request_loader 未處理「使用者已刪除」→ 全站 500

**(a) 問題與影響**
`funlab-auth/funlab/auth/view.py:register_login_handler.user_loader`（約 L338-343）直接 `user.user_folder = ...(user.username)`，`load_user` 回 `None`（帳號被删、或 cookie 內 id 不存在）時拋 `AttributeError`。實證：持有舊 session cookie 的使用者瀏覽**任何頁面**（含 /login 本身）→ **HTTP 500**（探針 `D1_deleted_user_cookie_status = 500`；棧經 appbase before_request 選單渲染，無一倖免）。`request_loader` 的 `session['user_id']` 分支（約 L348-351）同款崩潰（`D2b_request_loader_deleted = 500`）。這是證據包 **L9**，且影響面是「一個被刪帳號的 cookie 讓整站對該瀏覽器變 500」。

**(b) 優先級**：P0（可用性；且屬安全過濾鏈的必經點）

**(c) 目標**：`funlab/auth/view.py` 內 `register_login_handler()` 的 `user_loader`、`request_loader`。

**(d) 修正後程式碼**（整個 `register_login_handler` 可替換；request_loader 完整修法見 AUTH-04，兩項同檔同函式，**必須同一 PR 一起改**，此處先給 AUTH-01 範圍的最小正確版）：

```python
    def register_login_handler(self):
        @self.login_manager.unauthorized_handler
        def unauthorized_handler():
            wants_json = (
                request.is_json
                or request.path.startswith('/api/')
                or '/api/' in request.path
                or request.accept_mimetypes.best == 'application/json'
            )
            if wants_json:
                return jsonify({'error': 'authentication_required'}), 401
            return redirect(url_for(self.login_manager.login_view, next=request.url))

        @self.login_manager.user_loader
        def user_loader(id):
            with self.app.dbmgr.session_context() as session:
                user = load_user(id, session)
                if user is None:
                    # 帳號已刪除/id 不存在：回 None 讓 flask-login 走匿名+unauthorized 流程
                    return None
                user.user_folder = self.app.get_user_data_storage_path(user.username)
                return user

        @self.login_manager.request_loader
        def request_loader(request):
            with self.app.dbmgr.session_context() as sa_session:
                if 'user_id' in session:
                    user = load_user(session['user_id'], sa_session)
                    if user is None:
                        return None
                    user.user_folder = self.app.get_user_data_storage_path(user.username)
                    return user
            return None
```

> AUTH-04 的 (d) 給出含 OAuth Authorization 分支修正的**最終合併版**；coder 以 AUTH-04 版本為準，AUTH-01 版本僅供單獨 hotfix 用。

**(e) pytest**（`tests/integration/test_auth_loaders.py`，用 §0 fixture；此為修復後應 PASS 版，現行碼會 FAIL 即重現缺陷）：

```python
def test_user_loader_missing_user_returns_none(auth_app):
    assert auth_app.login_manager._user_callback("99999") is None

def test_deleted_user_cookie_anonymous_not_500(auth_app):
    c = auth_app.test_client()
    with c.session_transaction() as sess:
        sess["_user_id"] = "99999"; sess["_fresh"] = True
    r = c.get("/settings")
    assert r.status_code in (200, 302)      # 匿名處理（導向登入），絕不 500
    assert r.status_code != 500

def test_request_loader_stale_user_id_not_500(auth_app):
    c = auth_app.test_client()
    with c.session_transaction() as sess:
        sess["user_id"] = "99999"
    assert c.get("/settings").status_code != 500
```

對照現行缺陷的斷言見附錄 B `TestAUTH01_UsersLoaderCrash500`（現行碼 14 passed 佐證）。

**(f) 驗證**：`python -m pytest -q tests/integration/test_auth_loaders.py` 3 passed；`python -m pytest -q` 全套 ≥ 基線。
**(g) 風險/禁止**：不可在 user_loader 內建立使用者或目錄以外的副作用；`get_user_data_storage_path` 會 `mkdir`（funlab-flaskr app.py:92-94），回 None 前不要呼叫它。禁止把 except 吞成 `return AnonymousUserMixin()`（會繞過 flask-login 自家匿名物件語意）。

---

## AUTH-02（P1）/register 匿名全開放、繞過表單驗證、可自我鎖死註冊

**(a) 問題與影響**
`funlab-auth/funlab/auth/view.py:register`（約 L259-281）：
1. 無任何開關——公開部署時任何人都能建立 `state='active'` 帳號並立即登入（實證：`D3_register_status=200`、`D3_login_after_register=(302,'/home')`）。本系統帐号綁定券商憑證目錄（user_folder），公開自註冊=未授權者取得交易系統入口。
2. 直接 `request.form['username']` 取值、完全未呼叫 `AddUserForm.validate()`——Email 格式/長度驗證形同虛設（缺欄位時 400 來自 werkzeug ImmutableMultiDict KeyError→400：`D3_register_missing_fields=400`，属旁路幸運正確）。
3. 密碼可填 OAuth 佔位字串 → 註冊後帳號永不可密碼登入（見 AUTH-12）。
4. 重複 email 的 flash 渲染到 `register.html`，而該模板**沒有 flash 區塊**（grep `get_flashed_messages`=0）→ 使用者看不到「Email already registered」（見 AUTH-13）。

**(b) 優先級**：P1（部署面；本專案目前單人使用，但為公網服務前必修）

**(c) 目標**：`funlab/auth/view.py:register`；設定鍵 `ALLOW_REGISTER`（`[AuthView]` section）。

**(d) 修正後程式碼**（整個 `register` 路由可替換；含 AUTH-12 的佔位密碼擋堵）：

```python
        @self.blueprint.route('/register', methods=['GET', 'POST'])
        def register():
            from funlab.auth.user import EXTERNAL_AUTH_PLACEHOLDER
            # 預設關閉自助註冊；需於 [AuthView] 明示 ALLOW_REGISTER=true
            if not self.plugin_config.get('ALLOW_REGISTER', False):
                flash('Registration is disabled. Please contact administrator.', 'warning')
                return redirect(url_for(f'{self.bp_name}.login'))
            create_account_form = AddUserForm(request.form)
            if 'register' in request.form:
                if not create_account_form.validate():
                    flash('Invalid registration data. Please check the form.', 'warning')
                    return render_template('/register.html', form=create_account_form)
                username = request.form['username']
                email = request.form['email']
                password = request.form['password']
                if password == EXTERNAL_AUTH_PLACEHOLDER:
                    # 佔位字串會讓帳號被判定為 OAuth 帳號而永不可密碼登入（AUTH-12）
                    flash('Invalid password.', 'warning')
                    return render_template('/register.html', form=create_account_form)
                with self.app.dbmgr.session_context() as sa_session:
                    user = load_user(email, sa_session)
                    if user:
                        flash('Email already registered. Check it and register again.', category='warning')
                        return render_template('/register.html', form=create_account_form)
                    user = UserEntity(username=username, email=email, password=password,
                                      avatar_url='', state='active')
                    user.user_folder = self.app.get_user_data_storage_path(user.username)
                    sa_session.add(user)
                flash("Account is created successfully. Please login.", category='success')
                return render_template('sign-in.html', form=LoginForm(), oauths_info=self.oauths_info)
            return render_template('/register.html', form=create_account_form)
```

> 注意原碼 `logout_user()` 在成功分支前被呼叫（匿名状态下為無意圖副作用），修正版移除；`user.user_folder=` 保留（建立目錄，與現況一致）。

**(e) pytest**（`tests/integration/test_register.py`）：

```python
def test_register_closed_by_default(auth_app):
    c = auth_app.test_client()
    r = c.post('/register', data={'register': '1', 'username': 'm', 'email': 'm@x.io', 'password': '***'})
    assert r.status_code == 302                      # 導向登入
    assert b"Registration is disabled" in c.get('/login/').data

def test_register_placeholder_password_rejected(auth_app):
    # 僅在 ALLOW_REGISTER=true 的 app fixture 下執行（另建 app fixture 於 [AuthView] 加 ALLOW_REGISTER=true）
    from funlab.auth.user import EXTERNAL_AUTH_PLACEHOLDER
    c = auth_app.test_client()
    r = c.post('/register', data={'register': '1', 'username': 't', 'email': 't2@x.io',
                                  'password': EXTERNAL_AUTH_PLACEHOLDER})
    assert b"Invalid password" in _flash_all(c)      # flash 或 session 檢查
```

現行缺陷斷言見附錄 B `TestAUTH02_OpenRegistration`、`test_register_with_placeholder_password_locks_account`。

**(f) 驗證**：`python -m pytest -q tests/integration/test_register.py`；手工：預設設定 POST /register → 302 + flash，不再建立帳號。
**(g) 風險/禁止**：`finfun/config.toml [AuthView]` 現況**沒有** ALLOW_REGISTER 鍵→預設 false 是行為變更（原本可註冊）；PR 描述必須標示。禁止在關閉狀態下保留 /register 的 GET 表單（一并 redirect）。不得改 `AddUserForm` 欄位 id（模板綁定）。

---

## AUTH-03（P0）[AuthView] 內標量設定鍵令 AuthView 初始化炸毀 → 整站降回 PUBLIC（fail-open）

**(a) 問題與影響**
`view.py:AuthView.__init__`（約 L47-57）對 `plugin_config` **所有鍵**無條件 `oauth_cfg.pop('provider')`；但同一個 config 又被 L63 用來讀標量 `HOOK_EXAMPLES`。只要管理者在 `[AuthView]` 加任何標量鍵（文件自己暗示的 `HOOK_EXAMPLES=true` 即足），bool 沒有 `.pop` → `AttributeError` → `raise e from Exception(msg)`（此寫法另外吞掉語意：new Exception 只是 `__cause__`）→ plugin manager 捕獲構造例外，AuthView 載入失敗，app 照常啟動且 `security_mode=PUBLIC`、`authorization_enabled=False`（實證：`E3_scalar_key_auth_loaded=False`、`E3_scalar_key_security_mode=SecurityMode.PUBLIC`）。**效果：一個設定鍵讓全站驗證消失但服務繼續跑** —— 典型 fail-open。附帶發現：OAuth section 缺 `userinfo_endpoint` 等鍵時 `oauth.register()` 不在構造期驗證（`E4_broken_oauth_auth_loaded=True`），錯誤延後到第一次 OAuth 登入才爆——低危，記錄即可。

**(b) 優先級**：P0（認證總開關級）

**(c) 目標**：`funlab/auth/view.py:AuthView.__init__` OAuth 迴圈。

**(d) 修正後程式碼**（`__init__` 中 OAuth 註冊段可替換；其餘行不動）：

```python
        oauth = OAuth(app)
        oauth_configs: Config = self.plugin_config
        self.oauths: dict[str, dict] = {}
        default_userinfo_keys = {'email': 'email', 'username': 'username', 'avatar_url': 'avatar_url'}
        for oauth_name in list(oauth_configs.keys()):
            oauth_cfg = oauth_configs.get(oauth_name)
            # [AuthView] 內的標量鍵（HOOK_EXAMPLES / ALLOW_REGISTER …）不是 OAuth provider，跳過
            if not hasattr(oauth_cfg, 'pop'):
                continue
            provider = oauth_cfg.pop('provider', None)
            if provider is None:
                self.mylogger.warning(f"AuthView OAuth section '{oauth_name}' has no 'provider'; skipped")
                continue
            userinfo_key_mapping = copy.copy(default_userinfo_keys)
            userinfo_key_mapping.update(oauth_cfg.pop('userinfo_key_mapping', {}))
            try:
                oauth_register = oauth.register(name=oauth_name, **oauth_cfg)
            except Exception as e:
                # 單一 provider 設定壞掉不拖垮整個 AuthView（否則整站 fail-open）
                self.mylogger.error(f"{oauth_name} OAuth register fail, please check config: {e}")
                continue
            self.oauths.update({oauth_name: {'provider': provider, 'register': oauth_register,
                                             'userinfo_key_mapping': userinfo_key_mapping}})
        self.oauth_name_inuse: str = None
```

**(e) pytest**（`tests/integration/test_authview_init.py`；自建兩個 app，約 +60s）：

```python
def test_scalar_key_does_not_kill_authview(auth_app):
    # 以 CFG_TEMPLATE 加 "HOOK_EXAMPLES = true" 於 [AuthView] 下重建 FunlabFlask
    app = _make_app_with_auth_extra("HOOK_EXAMPLES = true\n")
    try:
        assert "auth" in app.plugins                      # AuthView 存活
        assert str(app.security_mode).endswith("SECURED") # 驗證仍生效
        assert list(app.plugins['auth'].oauths) == ['probe_google']  # provider 仍註冊
    finally:
        app.dbmgr.release()
```

現行缺陷斷言（auth 未載入 + PUBLIC）見附錄 B `test_AUTH03_scalar_config_key_degrades_to_public`（已 PASS 佐證）。

**(f) 驗證**：`python -m pytest -q tests/integration/test_authview_init.py`；另於 dev `finfun/config.toml [AuthView]` 加 `HOOK_EXAMPLES=true` 重啟，確認 /login 仍可登入且 security_mode SECURED。
**(g) 風險/禁止**：**跨倉事項（超出本檔授權，僅記錄不修）**：plugin_manager 捕獲 plugin 構造例外後繼續以 PUBLIC 啟動，才是 fail-open 根因；應向 dev-arch 提案「AuthView 宣告 `provides_security=true` 且構造失敗 → 啟動拒絕或強制 SECURED 拒服」。本 PR 禁止動 funlab-libs。跳過壞 provider 後 `oauth_name_inuse` 語意不變。

---

## AUTH-04（P1）request_loader 的 OAuth Authorization 分支：任意 token 直打 provider、失敗 500、無效期檢查

**(a) 問題與影響**
`view.py:register_login_handler.request_loader`（約 L345-366）：
1. 任何請求帶 `Authorization: <任意字串>`（或 `?google_token=`，token 還進 URL/日誌）且曾有使用者做過 OAuth 登入（`oauth_name_inuse` 為執行緒不安全的全域）時，把裸字串塞成 token 直接發 `userinfo()` **外呼** provider——無本地簽名/效期檢查，每个帶頭請求都產生一次外部 HTTP。
2. 外呼失敗（過期/亂碼）→ `raise Exception(...) from e` → 請求 500（實證：`V3_authorization_branch_status=500`、`V3b_google_token_param=500`）。
3. `get_userinfo_field_value` 讀 `self.oauth_name_inuse`（構造期後可變、跨請求共享），與 authorize 流程競態（authorize 例外路徑才清 None）。
4. token 為 dict（authorize 存 `session['oauth_token']=token`），但 request_loader 塞的是 **str**（無 `access_token` 鍵結構），語意不一致。
5. `authorize` 路由 `login_user(user)`（約 L244）未檢查回傳值：disabled 的 OAuth 帳號會得到「未登入但導向 /home」的困惑狀態（flask_login 0.6.3 `login_user` 對 `is_active=False` 回 False：實證 `V2_login_user_disabled_returns=False`）。

**(b) 優先級**：P1（可用性 DoS 面 + 外部呼叫放大器；非直接登入繞過——provider 仍验 token）

**(c) 目標**：`funlab/auth/view.py:register_login_handler.request_loader`（最終版，含 AUTH-01 的 None 處理）。

**(d) 修正後程式碼**（整個 `request_loader` 可替換）：

```python
        @self.login_manager.request_loader
        def request_loader(request):
            with self.app.dbmgr.session_context() as sa_session:
                if 'user_id' in session:
                    user = load_user(session['user_id'], sa_session)
                    if user is None:
                        return None
                    user.user_folder = self.app.get_user_data_storage_path(user.username)
                    return user

                oauth_name = self.oauth_name_inuse
                if not oauth_name:
                    return None
                try:
                    oauth_register = self.get_oauth_register(oauth_name)
                except (AttributeError, TypeError):
                    return None
                token = request.headers.get('Authorization') or request.args.get('google_token')
                if not token:
                    return None
                # 本地先剝 Bearer 前綴並做最小格式檢查；一切以 provider 回應為準，
                # 任何失敗一律回 None（走 unauthorized 流程），絕不把例外升格成 500
                token = token.removeprefix('Bearer ').strip()
                if len(token) < 20:
                    return None
                try:
                    oauth_register.token = {'access_token': token, 'token_type': 'Bearer'}
                    userinfo = oauth_register.userinfo()
                    user = load_user(self.get_userinfo_field_value(userinfo, 'email'), sa_session)
                    if user is None or not user.is_active:
                        return None
                    user.user_folder = self.app.get_user_data_storage_path(user.username)
                    return user
                except Exception as e:
                    self.mylogger.debug(f"request_loader oauth token rejected: {e}")
                    return None
            return None
```

> `get_oauth_register` 現況對不存在的 name 會 `None.get('register')`（view.py:150-153），故以 try 包裹；不該改動該 helper 的簽名（fundmgr 等外部有引用慣例）。

**(e) pytest**（`tests/integration/test_request_loader.py`，於 §0 fixture 之 app 將 `app.plugins['auth'].oauth_name_inuse='probe_google'` 後打無效 token；此 app 的 `[AuthView]` 需含一個指向 `https://nonexistent.invalid/...` 的假 provider，見附錄 B fixture）：

```python
def test_bearer_garbage_never_500(auth_app_oauth):
    auth_app_oauth.plugins['auth'].oauth_name_inuse = 'probe_google'
    r = auth_app_oauth.test_client().get('/settings', headers={'Authorization': '***'})
    assert r.status_code in (302, 401)          # 拒絕但不 500
    assert r.status_code != 500

def test_google_token_param_never_500(auth_app_oauth):
    auth_app_oauth.plugins['auth'].oauth_name_inuse = 'probe_google'
    assert auth_app_oauth.test_client().get('/settings?google_token=***').status_code != 500
```

現行缺陷版見附錄 B `TestAUTH04_RequestLoaderBearerBranch`。

**(f) 驗證**：`python -m pytest -q tests/integration/test_request_loader.py`；整合驗收：真 OAuth 登入取得 token 後以 `Authorization: Bearer <access_token>` 打受保護 API 仍可登入（正例不被誤殺）。
**(g) 風險/禁止**：本分支語意=「把 provider 當 IdP 複驗」，禁止改成本地解 JWT 簽名（無 jwks 快取設施，超出範圍）。禁止在此分支 `login_user()`（flask-login 自會處理 request_loader 回傳）。`google_token` query 參數建議標記 deprecation（token 入 URL 會進日誌）。

---

## AUTH-05（P1）/login 無速率限制

**(a) 問題與影響**
`view.py:login` 對同 email/同 IP 的連續錯密碼零成本：實測連打 20 次全 200（`D6b_bruteforce_20_codes={200}`）。bcrypt 拖慢單次嘗試但無鎖定＝線上密碼字典可無限跑；且錯密碼回 200 渲染頁、對的錯誤類型各有訊息，配合 AUTH-06 列舉風險放大。

**(b) 優先級**：P1

**(c) 目標**：`funlab/auth/view.py:login` + `AuthView.__init__`（狀態容器）。

**(d) 修正後程式碼**（記憶體滑窗，單程序部署足夠；多 worker 部署須換 app_cache/redis——本專案單 gunicorn 程序系，現況成立）：

`__init__` 加（`self.oauth_name_inuse` 之後）：

```python
        import threading as _threading
        self._login_attempts: dict[tuple, list[float]] = {}
        self._login_lock = _threading.Lock()

    def _login_rate_limited(self, key: tuple, limit: int = 5, window: int = 60) -> bool:
        """回傳 True 表示已超過 limit 次/window 秒。"""
        import time as _t
        now = _t.time()
        with self._login_lock:
            stamps = [s for s in self._login_attempts.get(key, []) if now - s < window]
            if len(stamps) >= limit:
                self._login_attempts[key] = stamps
                return True
            stamps.append(now)
            if len(self._login_attempts) > 10000:      # 防狀態無限膨脹
                self._login_attempts = {k: v for k, v in self._login_attempts.items() if now - max(v) < window}
            self._login_attempts[key] = stamps
            return False
```

`login` 路由在讀取表單後、查使用者前插入：

```python
            if 'login' in request.form:
                email = request.form.get('email', '')
                password = request.form.get('password', '')
                if (self._login_rate_limited(('ip', request.remote_addr))
                        or self._login_rate_limited(('acct', email.strip().lower()))):
                    flash('Too many login attempts. Please wait a minute and try again.', 'warning')
                    return render_template('/sign-in.html', form=login_form, oauths_info=self.oauths_info), 429
```

**(e) pytest**（`tests/integration/test_login_rate.py`）：

```python
def test_sixth_wrong_password_in_window_blocked(auth_app):
    c = auth_app.test_client()
    codes = [c.post('/login/', data={'login': '1', 'email': 'local@x.io', 'password': '***'}).status_code
             for _ in range(7)]
    assert codes[0] == 200 and codes[1] == 200     # 前 5 次正常處理
    assert codes[5] == 429 and codes[6] == 429     # 第 6、7 次被限流
```

**(f) 驗證**：`python -m pytest -q tests/integration/test_login_rate.py`；注意與附錄 A `test_wrong_password_is_rejected` 相容（單次嘗試不受影響）。
**(g) 風險/禁止**：記憶體窗在多 worker 下各自獨立（ weakened 但非無效）——如未來上多 worker，改用 `app.cache`；禁止把嘗試計數寫進 DB `user` 表（引入寫入路徑與鎖競爭）。鎖內禁止 DB/IO。

---

## AUTH-06（P2）登入訊息可列舉帳號（存在/OAuth/停用）

**(a) 問題與影響**
`view.py:login` 四種結果各給不同訊息（實證 body 層級 `V1_*`）：`User email not exist`（不存在）、`Incorrect password`（存在）、`account is from external authentication provider`（OAuth 帳號，且**不需要先對密碼**——`user.py:check_password_login` 先判 external）、`Account is not active`（存在但停用）。匿名攻擊者可一次 POST 完成帳號存在性 + 類型 + 狀態的完整列舉，供 AUTH-05 的密碼瞄準使用。

**(b) 優先級**：P2（單人系統風險有限；公開註冊關閉後降為防禦深度）

**(c) 目標**：`funlab/auth/view.py:login` 的 flash 分支；`funlab/auth/user.py:User.check_password_login`（順序微調，簽名不變）。

**(d) 修正後程式碼**：

login 分支（替換 `if not user:` 起的整個 if/elif 鏈）：

```python
                    user = load_user(email, session)
                    result = None if user is None else user.check_password_login(password)
                    if result == LOGIN_OK:
                        user.user_folder = self.app.get_user_data_storage_path(user.username)
                        login_user(user, remember=rememberme)
                        return redirect(url_for('root_bp.home'))
                    elif result == LOGIN_EXTERNAL_ACCOUNT:
                        # OAuth 帳號非機密（頁面本就列出 provider），保留引導訊息
                        flash('Your account is from external authentication provider, please login with proper provider below.', 'info')
                    elif result == LOGIN_INACTIVE:
                        flash("Account is not active. Please contact administrator.", 'warning')
                    else:
                        # 不存在與錯密碼共用同一訊息，杜絕列舉
                        flash("Invalid email or password. Please try again.", 'warning')
```

> `LOGIN_INACTIVE` 保留（聯絡管理員是必要支援資訊；停用帳號本就無法被攻擊，洩漏面最小）。若要求零洩漏可一併併入 Invalid 訊息——預設採上方版本。

**(e) pytest**（`tests/integration/test_login_messages.py`）：

```python
def test_nonexistent_and_wrong_password_same_message(auth_app):
    c = auth_app.test_client()
    r1 = c.post('/login/', data={'login': '1', 'email': 'ghost@x.io', 'password': '***'})
    r2 = c.post('/login/', data={'login': '1', 'email': 'local@x.io', 'password': '***'})
    assert b"Invalid email or password" in r1.data and b"Invalid email or password" in r2.data
    assert b"User email not exist" not in r1.data
```

**(f) 驗證**：`python -m pytest -q tests/integration/`（含附錄 A 檔——注意附錄 A 無斷言依賴 'Incorrect password' 字樣，實跑核對過）。
**(g) 風險/禁止**：改訊息不得改 `check_password_login` 回傳常數集（tests/unit/test_login_check.py 鎖住）。禁止對不存在使用者 skip bcrypt 造成時間差側信道（上方寫法錯密碼與不存在都走一次 bcrypt？——不存在時 user=None 跳過 verify：如在乎 timing，補 `User.dummy_verify(password)`；本檔列為可選後續，不列入本項驗收）。

---

## AUTH-07（P1）logout 用 GET 且無 CSRF → 跨站強制登出

**(a) 問題與影響**
`view.py:logout`（約 L251-257）只掛 GET。全域 CSRFProtect（funlab-flaskr）只管 POST/PUT/PATCH/DELETE，GET 天然豁免 → 任意頁面 `<img src="https://host/logout">` 即可把登入中的使用者踢出（實證：`D7_logout_get_status=302` 生效；`D7_logout_post_status=405` 無 POST）。危害級別低（登出型 CSRF），但選單連結與之綁死，修法須兼顧現有 `<a href='/logout'>` 選單項。

**(b) 優先級**：P1（修法涉及 UX，須在 P2 前處理）

**(c) 目標**：`funlab/auth/view.py:logout`；`funlab/auth/templates/logout.html`（該模板現況**未被任何路由引用**，正好啟用為確認頁）。

**(d) 修正後程式碼**：

```python
        @self.blueprint.route('/logout', methods=['GET', 'POST'])
        @login_required
        def logout():
            # GET 不再直接登出（防跨站 <img src=/logout>）；GET 顯示確認頁，POST 才登出
            if request.method == 'GET':
                return render_template('logout.html')
            logout_user()
            session.pop('oauth_token', None)
            session.pop('user_id', None)
            return redirect(url_for('root_bp.index'))
```

`logout.html` 於 `<h1>Logout</h1>` 後加入表單（模板其他部分不動）：

```html
<form method="post" action="{{ url_for('auth_bp.logout') }}">
  {{ form.hidden_tag() if form }}
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <button type="submit" class="btn btn-danger">Confirm Logout</button>
</form>
```

**(e) pytest**（`tests/integration/test_logout.py`）：

```python
def test_get_logout_shows_confirmation_not_logout(auth_app):
    c = auth_app.test_client()
    c.post('/login/', data={'login': '1', 'email': 'local@x.io', 'password': PASSWORD})
    r = c.get('/logout')
    assert r.status_code == 200                      # 確認頁，非 302
    with c.session_transaction() as sess:
        assert '_user_id' in sess                    # 尚未登出

def test_post_logout_logs_out(auth_app):
    c = auth_app.test_client()
    c.post('/login/', data={'login': '1', 'email': 'local@x.io', 'password': PASSWORD})
    r = c.post('/logout')
    assert r.status_code == 302
    with c.session_transaction() as sess:
        assert '_user_id' not in sess
```

（執行於 `WTF_CSRF_ENABLED=False` fixture；CSRF token 由全域 CSRFProtect 在正式環境強制。）

**(f) 驗證**：`python -m pytest -q tests/integration/test_logout.py`；手工走一遍選單 Logout → 確認頁 → Confirm → 登出。
**(g) 風險/禁止**：選單項（view.py:setup_menus）href 不動（GET→確認頁自然相容）；禁止在 GET 分支保留登出「相容性开关」等於沒修。若 funlab-flaskr 有自動化腳本直接 GET /logout，交付時須通知（grep 現況僅 finfun-fundmgr qa_tools 用 session 注入，不受影響）。

---

## AUTH-08（P2）登入不輪換/不清空 session（會話固定殘留）

**(a) 問題與影響**
`login_user()`（flask_login 0.6.3）只寫入 `_user_id` 等鍵，不清舊鍵；實證登入前植入的 `attacker_key` 在登入後仍存活（`D5_prelogin_key_survives=True`）。本專案是簽名 cookie session（stateless，`V4_session_type='(unset → Flask signed cookie)'`），傳統「誘導固定 JSESSIONID」不成立，但**攻擊者可在受害者共用瀏覽器上預植鍵**、受害者登入後鍵仍掛在其 session；插件未來若引入信任任意 session 鍵的功能（如 OAuth state、return_to）即成注入面。屬防禦深度必修。

**(b) 優先級**：P2

**(c) 目標**：`view.py:login`（LOGIN_OK 分支）、`view.py:authorize`（login_user 前）。

**(d) 修正後程式碼**：

login 分支：

```python
                        if result == LOGIN_OK:
                            user.user_folder = self.app.get_user_data_storage_path(user.username)
                            session.clear()   # 登入手勢：丟棄匿名期 session，防固定/殘留
                            login_user(user, remember=rememberme)
                            return redirect(url_for('root_bp.home'))
```

authorize 路由（`session['oauth_token'] = token` 一行之前）：

```python
                session.clear()          # 清掉 _oauth_login_start 與匿名期殘留鍵
                session['oauth_token'] = token
                if not login_user(user):
                    flash("Account is not active. Please contact administrator.", 'warning')
                    return render_template('sign-in.html', form=LoginForm(), oauths_info=self.oauths_info)
                return redirect(url_for('root_bp.home'))
```

> 同時修 AUTH-04(a)(5)：disabled OAuth 帳號現在會得到明確訊息而非困惑導向。
> 注意 authlib 的 OAuth state 存在**請求前**已寫入的 session 中，`authorize_access_token()` 已於此行之前完成校驗（view.py:211 先執行），故 `session.clear()` 放此處安全——**不可**移到 `authorize_redirect` 之後、校驗之前。

**(e) pytest**（`tests/integration/test_session_rotation.py`）：

```python
def test_prelogin_key_cleared_on_login(auth_app):
    c = auth_app.test_client()
    with c.session_transaction() as sess:
        sess['attacker_key'] = 'planted'
    c.post('/login/', data={'login': '1', 'email': 'local@x.io', 'password': PASSWORD})
    with c.session_transaction() as sess:
        assert 'attacker_key' not in sess and '_user_id' in sess
```

**(f) 驗證**：`python -m pytest -q tests/integration/test_session_rotation.py` 且附錄 A 全綠（成功流程斷言 `_user_id` 消失靠 logout_user，不受影響）。
**(g) 風險/禁止**：`session.clear()` 必須在 `login_user()` **前**、OAuth 的 `authorize_access_token()` **後**；位置錯誤會破壞 authlib state 驗證或白清。禁止順手清 `REMEMBER_COOKIE_*` 設定。

---

## AUTH-09（P2）next 參數：絕對 URL 反射 + 登入後不跟隨（現況良性，支援 next 時必須白名單）

**(a) 問題與影響**
`view.py:unauthorized_handler`（約 L336）`redirect(url_for(login_view, next=request.url))` 把**完整絕對 URL**塞進 next；`login` 成功後固定導向 home、完全忽略 next（實證 `D4_unauthorized_location='/login/?next=http://localhost/settings'`）。現況無 open redirect（沒人跟隨 next），但这是「差一個好意 PR」的經典地雷：一旦有人補上 `redirect(request.args['next'])` 即成釣魚跳板。提前立規矩。

**(b) 優先級**：P2

**(c) 目標**：`funlab/auth/view.py`（新增模組級 helper；login 成功分支使用）。

**(d) 修正後程式碼**：

模組層（imports 之後）：

```python
from urllib.parse import urlparse

def _safe_next(raw: str | None, default_endpoint: str = 'root_bp.home') -> str:
    """只接受本站相對路徑；絕對 URL／協議相對 URL／非 '/' 開頭一律回預設。"""
    if raw:
        p = urlparse(raw)
        if not p.scheme and not p.netloc and raw.startswith('/') and not raw.startswith('//'):
            return raw
    return url_for(default_endpoint)
```

login 成功分支取代 `return redirect(url_for('root_bp.home'))`：

```python
                            return redirect(_safe_next(request.args.get('next') or request.form.get('next')))
```

**(e) pytest**（`tests/integration/test_safe_next.py`）：

```python
def test_external_url_in_next_is_ignored(auth_app):
    c = auth_app.test_client()
    r = c.post('/login/?next=https://evil.example.com/pw?d=', data={'login': '1', 'email': 'local@x.io', 'password': PASSWORD})
    assert r.headers['Location'] == url_for('root_bp.home')  # 絕不跳外部

def test_relative_next_followed(auth_app):
    c = auth_app.test_client()
    r = c.post('/login/?next=/settings', data={'login': '1', 'email': 'local@x.io', 'password': PASSWORD})
    assert r.headers['Location'] == '/settings'
```

**(f) 驗證**：`python -m pytest -q tests/integration/test_safe_next.py`。
**(g) 風險/禁止**：禁止實作 `redirect(request.args.get('next', ...))` 裸跟隨（本倉程式碼審查紅線）；`//evil.com` 協議相對形式已在 helper 擋掉，禁止簡化成只查 `startswith('/')`。

---

## AUTH-10（P1）utils.load_user 的 bare except（證據包 L10 後半）

**(a) 問題與影響**
`funlab-auth/funlab/auth/utils.py:load_user`（約 L28-32）：`try: id=int(id_email) ... except: stmt = ...email...`。裸 except 把任何 DB/型別異常誤判為「不是數字→查 email」：查詢條件錯誤、DB 斷線都會被吞掉再以「查無此人」形態浮現（實測 `load_user(None)` 平安回 None：`D11_load_user_none=None`——語意湊巧對，但同路徑下真正的 DB 錯同樣被吞）。

**(b) 優先級**：P1（診斷性/正確性；非直接漏洞）

**(c) 目標**：`funlab/auth/utils.py:load_user`。

**(d) 修正後程式碼**（整個函式可替換，docstring 精簡以便對照）：

```python
def load_user(id_email, sa_session: Session, classes='*') -> Type[UserEntity] | None:
    """用 id（純數字字串/整數）或 email 載入 UserEntity 及其 single-table 子孫。"""
    if classes == '*':
        User = UserEntity
    else:
        User = with_polymorphic(UserEntity, classes=classes)
    try:
        id = int(id_email)
        stmt = select(User).where(User.id == id)
    except (TypeError, ValueError):
        # 非整數輸入（email、None、亂字串）→ 依 email 查詢；
        # 其他例外（DB 故障等）必須上拋，不得誤判為查無此人
        if id_email is None:
            return None
        stmt = select(User).where(User.email == id_email)
    user = sa_session.execute(stmt).scalar()
    return user
```

**(e) pytest**（追加到 `tests/unit/test_auth_user.py` 同層新檔 `tests/unit/test_load_user.py`——沿用既有 conftest stub，不需完整 app，但 load_user 需真 sqlalchemy session；用 in-memory sqlite 直接建表）：

```python
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from funlab.auth.user import UserEntity, entities_registry
from funlab.auth.utils import load_user

@pytest.fixture()
def sa_session():
    eng = create_engine("sqlite:///:memory:")
    entities_registry.metadata.create_all(eng)
    with Session(eng) as s:
        s.add(UserEntity(username='a', email='a@b.io', password='***', avatar_url='', state='active'))
        s.commit()
        yield s

def test_load_by_email_and_id(sa_session):
    assert load_user('a@b.io', sa_session).username == 'a'
    assert load_user(str(load_user('a@b.io', sa_session).id), sa_session).email == 'a@b.io'

def test_none_returns_none(sa_session):
    assert load_user(None, sa_session) is None

def test_db_error_propagates(sa_session):
    sa_session.close()          # 模擬底層故障：後續 execute 拋 SQLALchemyError，不得被吞
    with pytest.raises(Exception):
        load_user('a@b.io', sa_session)
```

**(f) 驗證**：`python -m pytest -q tests/unit`（新檔 + 既有 19 passed 不破壞）。
**(g) 風險/禁止**：禁止改成 `try/except Exception` 再 log 吞掉——必須只接 `(TypeError, ValueError)`。呼叫端（view 各路由）對 None 的處理由 AUTH-01/02 負責，本項不得順手改 view。

---

## AUTH-11（P2）role=None 令 is_anonymous 拋例外

**(a) 問題與影響**
`funlab/auth/user.py:User.is_anonymous`（約 L67-69）`self.role.upper()`；`role` 欄可為 NULL（DB 直接寫入、歷史資料、其他系統寫 user 表——polymorphic 欄並非四處受控），None 時任何觸碰 `current_user.is_anonymous` 的請求 500（實證 `D12_is_anonymous_none_role = AttributeError`）。與 AUTH-01 同族「None 炸全站」。

**(b) 優先級**：P2

**(c) 目標**：`funlab/auth/user.py:User.is_anonymous`。

**(d) 修正後程式碼**：

```python
    @property
    def is_anonymous(self):
        role = getattr(self, 'role', None)
        return bool(role) and str(role).upper() == 'GUEST'
```

**(e) pytest**（追加至 `tests/unit/test_login_check.py` 或新檔 `tests/unit/test_user_props.py`）：

```python
def test_is_anonymous_none_role_no_raise():
    from funlab.auth.user import User
    u = User(email='a@b.io', username='a', password='***', avatar_url='', state='active')
    u.role = None
    assert u.is_anonymous is False

def test_is_anonymous_guest_true():
    from funlab.auth.user import User
    u = User(email='a@b.io', username='a', password='***', avatar_url='', state='active')
    u.role = 'Guest'
    assert u.is_anonymous is True
```

**(f) 驗證**：`python -m pytest -q tests/unit`。
**(g) 風險/禁止**：`to_userentity()` 對 is_admin 的 `None→False` 依賴 `__post_init__` 的 getattr 守衛（user.py:43-45），本項勿動該邏輯。禁止把 role 比較改成大小寫敏感（現有 'GUEST' 慣例）。

---

## AUTH-12（P2）以 OAuth 佔位密碼註冊 → 帳號自我鎖死

**(a) 問題與影響**
`user.py:__post_init__`（約 L46-47）把 password==None 設為 `EXTERNAL_AUTH_PLACEHOLDER`，`is_external_account()` 用「能否 verify 該明文」判別 OAuth 帳號。任何使用者若（故意或誤貼）以佔位字串作為註冊密碼，雜湊後的結果與 OAuth 帳號**不可區分** → `check_password_login` 永遠回 `LOGIN_EXTERNAL_ACCOUNT` → 該帳號永不可密碼登入、也無 OAuth 通道（實證：`V9_selflock=(200, True)`，登入被導向「請用外部 provider」）。

**(b) 優先級**：P2（自我 DoS；正解在入口擋堵，即 AUTH-02 (d) 已含 `password == EXTERNAL_AUTH_PLACEHOLDER` 拒絕）

**(c) 目標**：入口擋堵見 `view.py:register`（AUTH-02）；模型層補強見下。

**(d) 追加修正（選做，模型層）**：`user.py:User.verify_pass` 之後新增供 resetpass 使用的明確閘門——**不做**（維持佔位判定現狀），仅在文件記錄：若未來支援「OAuth 帳號補設密碼」，必須改用獨立欄位（如 `auth_provider`）而非密碼內容探測。驗收以 AUTH-02 入口擋堵為準。

**(e) pytest**：見 AUTH-02 (e) 第二案例 + 附錄 B `test_register_with_placeholder_password_locks_account`（現行 PASS＝缺陷存在；AUTH-02 修復後此測試 FAIL 屬預期，反轉為 `assert b"Invalid password" in ...`）。

**(f)/(g)**：同 AUTH-02。禁止改 `EXTERNAL_AUTH_PLACEHOLDER` 字面值（既有 OAuth 帳號雜湊綁死舊值，改值=所有 OAuth 帳號變成可設密碼）。

---

## AUTH-13（P2）/resetpass、/register、/settings 模板無 flash 區塊 → H3 修復的拒絕訊息使用者不可見

**(a) 問題與影響**
grep 實證：`resetpass.html`、`register.html`、`settings.html` 的 `get_flashed_messages` 計數 **0**（`sign-in.html` 有）。H3 修復後 resetpass 的各拒絕路徑都靠 flash（「You can only change your own password.」等），但重渲染的 resetpass.html 不顯示 flash → 使用者按送出後「什麼都沒發生」。同理 register 的重複 email 提示不可見。安全行為正確但 UX 沉默，使用者會重複提交或誤判成功。

**(b) 優先級**：P2

**(c) 目標**：`funlab/auth/templates/resetpass.html`、`register.html`（settings.html 視需要）。

**(d) 修正後模板片段**（插入 `resetpass.html` 的 `{% block page_body %}` 後、表單卡片之前；register.html 同位置同片段）：

```html
    <div class="text-left">
      {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
      <div class="alert-container">
        {% for category, message in messages %}
        <div class="alert alert-{{ category }} fade show" role="alert">{{ message }}</div>
        {% endfor %}
      </div>
      {% endif %}
      {% endwith %}
    </div>
```

**(e) pytest**（`tests/integration/test_flash_visible.py`）：

```python
def test_resetpass_rejection_flash_visible_in_body(auth_app):
    c = auth_app.test_client()
    c.post('/login/', data={'login': '1', 'email': 'local@x.io', 'password': PASSWORD})
    r = c.post('/resetpass', data={'resetpass': '1', 'email': 'other@x.io',
                                   'old_password': 'x', 'new_password': 'N', 'confirm_password': 'N'})
    assert b"your own password" in r.data       # 修復前：只在 session，body 無此字樣
```

**(f) 驗證**：`python -m pytest -q tests/integration/test_flash_visible.py`；注意與附錄 A 相容（A 用 session 層斷言，不受模板影響）。
**(g) 風險/禁止**：模板改動只准新增 flash 區塊，禁止順改表單欄位 id/name；flash category 直接插入 class 現況已有（sign-in 同款），維持一致即可。

---

## AUTH-14（P2）/authorize 例外細節 flash 洩漏 + token 明文存簽名 cookie

**(a) 問題與影響**
`view.py:authorize`（約 L223、L248）把例外原文 flash 給瀏覽器（`f'Exception:{str(e)}'`）——例外常含 endpoint URL、內部堆疊語意，供攻擊者探測；且 `session['oauth_token'] = token`（L243）把 provider **存取權杖完整**放入簽名 cookie：簽名≠加密，瀏覽器持有者可讀（flask session 僅 base64+簽名），31 天有效（`V6_session_permanent_lifetime='31 days'`）且 `/logout` 才清。token 外洩=該 Google 帳號 API 存取權（scope: openid email profile，屬輕度，但屬憑證管理瑕疵）。

**(b) 優先級**：P2

**(c) 目標**：`funlab/auth/view.py:authorize`。

**(d) 修正後程式碼**（authorize 中三處替換）：

```python
            except Exception as e:
                self.mylogger.exception("authorize_access_token exception")
                flash('OAuth sign-in failed. Please try again.', category='danger')   # 細節只進 log
                return render_template('sign-in.html', form=LoginForm(), oauths_info=self.oauths_info)
```

（第二個 except 同改 `flash('Get userinfo from OAuth provider failed. Please try again.', category='danger')`。）

token 存放（配合 AUTH-08 的 session.clear 段）：

```python
                session.clear()
                # 只存 id_token 存在性與時間戳；access_token 如需 API 續用應放 app.cache（server-side）
                session['oauth_login_at'] = int(time.time())
                if not login_user(user):
                    ...
```

若下游（request_loader/AUTH-04 版）**不需要** server-side token（本方案不需要——每次自帶 token），可逕行移除 `session['oauth_token']`；`logout` 對它的 `session.pop` 保留无害。

**(e) pytest**：

```python
def test_oauth_failure_flash_has_no_exception_text(auth_app):
    # GET /authorize/probe_google 無 code 參數 → 失敗路徑
    r = auth_app.test_client().get('/authorize/probe_google')
    assert b'Exception:' not in r.data
```

**(f) 驗證**：`python -m pytest -q tests/integration`；手動斷網模擬 OAuth 失敗看頁面不含 endpoint/堆疊字樣。
**(g) 風險/禁止**：移除 `session['oauth_token']` 前必須 grep 全 workspace 確認無消費者（本輪查得僅 view.py 自产自清）；禁止順便在 flash 放 `type(e).__name__`（探測面）。

---

## 實施順序與 PR 切分

| 波次 | 項目 | 理由 |
|---|---|---|
| PR-1（hotfix，可先行） | AUTH-01 + AUTH-10 | 同族 None/例外鏈路，單檔小改，先止血 500 |
| PR-2 | AUTH-03（+AUTH-14） | 認證總開關；AUTH-14 同在 authorize/__init__ 周邊 |
| PR-3 | AUTH-04 + AUTH-08 | 同檔 register_routes/register_login_handler，強制同 PR 免互踩 |
| PR-4 | AUTH-02（含 12） | 行為變更，需部署端 config 確認 |
| PR-5 | AUTH-05 + AUTH-06 | login 訊息與限流同檔 |
| PR-6 | AUTH-07 + AUTH-09 + AUTH-13 | UX/模板面打包 |

每 PR 驗收：`cd funlab-auth && python -m pytest -q` 全綠（≥19 passed 基線 + 新增）；對應附錄 B 測試轉為反轉斷言。

## 已修復項目的防回歸測試（H2/H3）

完整檔：`tests/integration/test_auth_routes.py`（內容＝附錄 A，實跑 **15 passed**，約 9 秒）。覆蓋：錯誤密碼拒登+無 session、正確密碼 302、無 rememberme 欄位不 400、remember _cookie 有/無、OAuth 佔位密碼與已知佔位明文皆拒、disabled 拒登；resetpass 匿名 302 導登入、改他人被拒+目標密碼未變、OAuth 帳號設密被拒、錯舊密碼不改密、確認不符 200、成功流程改密+登出+新密碼可登。

## 附錄 A：tests/integration/test_auth_routes.py（防回歸，實跑 15 passed）

全文見 [`snippets/test_auth_routes.py`](snippets/test_auth_routes.py)；交付時由 coder 複製到 `funlab-auth/tests/integration/`（搭配 §0 的 `tests/integration/conftest.py`）。

## 附錄 B：tests/integration/test_auth_defects.py（缺陷重現，實跑 14 passed）

全文見 [`snippets/test_auth_defects.py`](snippets/test_auth_defects.py)（自帶 fixture，不依賴 conftest）。修復某項後對應測試 FAIL = 修復生效；屆時按該項 (e) 反轉併入防回歸集，最終刪除此檔。

## 附錄 C：實證輸出摘要（2026-09-27，tmp sqlite + test_client）

```
E1_plugins_loaded=['auth','fundmgr','option','quote','sched','sse'] E1_security_mode=SECURED E1_provider=AuthView
E2_csrf_ext=True E2_post_without_csrf=400            # 全域 CSRFProtect 生效（funlab-flaskr ADR-016）
E3_scalar_key_auth_loaded=False E3_scalar_key_security_mode=PUBLIC   # AUTH-03 fail-open 重現
E4_broken_oauth_auth_loaded=True                      # OAuth 壞設定延後爆（構造期不驗）
D1_deleted_user_cookie_status=500                     # AUTH-01
D2_user_loader_missing="AttributeError: 'NoneType' object has no attribute 'username'"
D2b_request_loader_deleted=500                        # AUTH-01 request_loader 分支
D3_register_status=200 D3_login_after_register=(302,'/home') D3_register_missing_fields=400   # AUTH-02
D4_unauthorized_location='/login/?next=http://localhost/settings'   # AUTH-09
D5_prelogin_key_survives=True D5_remember_cookie_on_rememberme=True # AUTH-08 / H2 rememberme 正常
D6b_bruteforce_20_codes={200}                         # AUTH-05
V1_not_exist_body=True V1_bad_pw_body=True V1_inactive_body=True    # AUTH-06 三種可區分訊息
V2_login_user_disabled_returns=False                  # flask_login 0.6.3 行為（AUTH-04(a)(5)）
V3_authorization_branch_status=500 V3b_google_token_param=500       # AUTH-04
V3_shared_register_object=True V3_token_storage_backend='flask.g (per-request)'  # token 暫存 g，無跨請求殘留
V4_session_type='(unset → Flask signed cookie)' V6_session_permanent_lifetime='31 days'
V7/V8 oauth 佔位/已知佔位登入皆拒（H2 生效）
V9_selflock=(200,True)                                # AUTH-12
D7_logout_get_status=302 D7_logout_post_status=405    # AUTH-07
D8_authlib_version=1.6.12 D8_state_in_create_authorization_url=True # state 由 authlib 自動產生/校驗（未見缺陷）
D11_load_user_none=None                               # AUTH-10 bare except 吞掉一切
D12_is_anonymous_none_role=AttributeError             # AUTH-11
D13_newbie: is_admin=False role='user' state='active' # 註冊不提權（無缺陷，記錄）
funlab-auth 基線: 19 passed；附錄A 15 passed；附錄B 14 passed
```

## 附錄 D：無法核實／僅記錄的事項

1. **OAuth 端到端流程**（真 provider 互動、state/nonce 實際校驗、id_token 簽名）：探針不觸網，未驗證 `authorize_access_token()` 對惡意 callback 的完整抵抗；authlib 1.6.12 原始碼顯示 state 自動生成/校驗（附錄 C D8），nonce 僅在 id_token 路徑由 authlib 處理。列為代碼審查信任項。
2. **多 worker 行為**：AUTH-05 記憶體限流、`oauth_name_inuse` 全域態在 gunicorn 多 worker 下的實際併發語意未實測。**現況不可能多 worker**：開發 venv 實查未安裝 gunicorn（`site-packages` 僅 authlib 1.6.12＋waitress 3.0.2），正式機走 waitress 單進程；該語意問題只在 Q6 裁示改走 gunicorn 後才成立。
3. **plugin fail-open 根因**（AUTH-03 備註）：屬 funlab-libs/plugin_manager 範疇，本檔無權限修改，已建議跨倉提案。現況緩解事實：`finfun/config.toml` 實查無 `HOOK_EXAMPLES` 鍵、`[AuthView]` 下現僅 OAuth 表結構（`funlab_google`），即目前**無存量觸發**；風險在「日後有人加任何標量鍵」。
4. **正式庫既有資料**（2026-09-27 已補查，唯讀）：`fundlife."user"` 共 5 列，`role IS NULL`＝0、`state IS NULL`＝0（分佈 manager 2／user 2／supervisor 1）→ AUTH-11 現況**無存量觸發**；修復仍建議做（新增資料無 NOT NULL 約束保護）。探針：scratch/probe_role_null.py。
