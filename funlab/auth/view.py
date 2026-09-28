
import copy
import time
from urllib.parse import urlparse

from authlib.integrations.flask_client import OAuth
from flask import (flash, jsonify, redirect, render_template, request,
                    session, url_for)
from flask_login import (
    LoginManager, current_user, login_required, login_user, logout_user
)
from funlab.auth.utils import load_user, save_user
from funlab.core.plugin import Plugin
from funlab.core.menu import MenuDivider, MenuItem
from funlab.core.config import Config
from funlab.flaskr.app import FunlabFlask

from .forms import AddUserForm, LoginForm, ResetPassForm
from .user import (LOGIN_EXTERNAL_ACCOUNT, LOGIN_INACTIVE, LOGIN_OK,
                   OAuthUser, UserEntity, entities_registry)


def _safe_next(raw: str | None, default_endpoint: str = 'root_bp.home') -> str:
    """AUTH-09：只接受本站相對路徑；絕對 URL／協議相對 URL／非 '/' 開頭一律回預設。

    紅線（PLAN (g)）：禁止簡化成只查 startswith('/')——'//evil.com' 協議相對
    形式必須一併擋掉。
    """
    if raw:
        p = urlparse(raw)
        if not p.scheme and not p.netloc and raw.startswith('/') and not raw.startswith('//'):
            return raw
    return url_for(default_endpoint)


class AuthView(Plugin):
    """Authentication plugin.

    Inherits :class:`~funlab.core.plugin.Plugin` directly and satisfies
    :class:`~funlab.core.plugin.ISecurityProvider` structurally by exposing
    a ``login_manager`` property.  No dependency on ``SecurityPlugin`` is
    required; the plugin manager detects this plugin as a security provider
    via duck-typing (``ISecurityProvider`` runtime-checkable Protocol).
    """

    def __init__(self, app: FunlabFlask):
        super().__init__(app, url_prefix="")
        # Reuse app-owned LoginManager when available; otherwise fallback-create.
        self._login_manager = getattr(app, 'login_manager', None) or LoginManager()
        if getattr(app, 'login_manager', None) is None:
            self._login_manager.init_app(app)
        self._login_manager.login_view = self.bp_name + ".login"
        self._login_manager.login_message = "Please log in to access this page."
        self._login_manager.login_message_category = "warning"
        self._login_manager.needs_refresh_message_category = "info"
        import finfun.core.entity.manager
        oauth = OAuth(app)
        oauth_configs:Config = self.plugin_config
        self.oauths: dict[str, dict] = {}
        default_userinfo_keys = {'email':'email', 'username':'username', 'avatar_url':'avatar_url'}
        for oauth_name in list(oauth_configs.keys()):
            oauth_cfg = oauth_configs.get(oauth_name)
            # [AuthView] 內的標量鍵（HOOK_EXAMPLES / ALLOW_REGISTER …）不是 OAuth provider，跳過
            if not hasattr(oauth_cfg, 'pop'):
                continue
            provider = oauth_cfg.pop('provider', None)
            if provider is None:
                self.mylogger.warning(f"AuthView OAuth section '{oauth_name}' has no 'provider'; skipped")
                continue
            userinfo_key_mapping =  copy.copy(default_userinfo_keys)
            userinfo_key_mapping.update(oauth_cfg.pop('userinfo_key_mapping', {}))
            try:
                oauth_register = oauth.register(name=oauth_name, **oauth_cfg)
            except Exception as e:
                # 單一 provider 設定壞掉不拖垮整個 AuthView（否則整站 fail-open）
                self.mylogger.error(f"{oauth_name} OAuth register fail, please check config: {e}")
                continue
            self.oauths.update({oauth_name: {'provider':provider, 'register':oauth_register, 'userinfo_key_mapping':userinfo_key_mapping}})
        self.oauth_name_inuse:str = None
        # AUTH-05（Q4 裁示：per-IP + per-email 記憶體計數；單進程 waitress 前提，
        # 不引入外部儲存依賴）：滑窗限流狀態容器
        import threading as _threading
        self._login_attempts: dict[tuple, list[float]] = {}
        self._login_lock = _threading.Lock()
        self.register_routes()
        self.register_login_handler()
        if hasattr(self._login_manager, '_default_user_loader'):
            delattr(self._login_manager, '_default_user_loader')
        if self.plugin_config.get('HOOK_EXAMPLES', False):
            self._register_hook_examples()

    def _register_hook_examples(self):
        if not hasattr(self.app, 'hook_manager'):
            return

        self.app.hook_manager.register_hook(
            'view_layouts_base_html_head',
            self._hook_example_head,
            priority=50,
            plugin_name=self.name,
        )
        self.app.hook_manager.register_hook(
            'controller_before_request',
            self._hook_example_before_request,
            priority=50,
            plugin_name=self.name,
        )
        self.app.hook_manager.register_hook(
            'controller_after_request',
            self._hook_example_after_request,
            priority=50,
            plugin_name=self.name,
        )

    def _hook_example_head(self, context):
        return '<!-- auth hook example -->'

    def _hook_example_before_request(self, context):
        request = context.get('request')
        if request:
            self.mylogger.debug(f"Hook example: auth before_request {request.path}")

    def _hook_example_after_request(self, context):
        response = context.get('response')
        if response:
            self.mylogger.debug(f"Hook example: auth after_request {response.status_code}")

    def _perform_health_check(self) -> bool:
        if getattr(self, '_blueprint_registered', True) is False:
            return False
        if getattr(self.app, 'login_manager', None) is None:
            return False
        return True

    def setup_menus(self):
        super().setup_menus()
        self.app.append_usermenu([MenuItem(title='Settings',
                    icon='<svg xmlns="http://www.w3.org/2000/svg" class="icon icon-tabler icon-tabler-settings" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">\
                            <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>\
                            <path d="M10.325 4.317c.426 -1.756 2.924 -1.756 3.35 0a1.724 1.724 0 0 0 2.573 1.066c1.543 -.94 3.31 .826 2.37 2.37a1.724 1.724 0 0 0 1.065 2.572c1.756 .426 1.756 2.924 0 3.35a1.724 1.724 0 0 0 -1.066 2.573c.94 1.543 -.826 3.31 -2.37 2.37a1.724 1.724 0 0 0 -2.572 1.065c-.426 1.756 -2.924 1.756 -3.35 0a1.724 1.724 0 0 0 -2.573 -1.066c-1.543 .94 -3.31 -.826 -2.37 -2.37a1.724 1.724 0 0 0 -1.065 -2.572c-1.756 -.426 -1.756 -2.924 0 -3.35a1.724 1.724 0 0 0 1.066 -2.573c-.94 -1.543 .826 -3.31 2.37 -2.37c1 .608 2.296 .07 2.572 -1.065z"></path>\
                            <path d="M9 12a3 3 0 1 0 6 0a3 3 0 0 0 -6 0"></path>\
                            </svg>',
                    href=f'/settings'),
                    MenuDivider(),
                    MenuItem(title='Logout',
                        icon='<svg xmlns="http://www.w3.org/2000/svg" class="icon icon-tabler icon-tabler-logout" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">\
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>\
                                <path d="M14 8v-2a2 2 0 0 0 -2 -2h-7a2 2 0 0 0 -2 2v12a2 2 0 0 0 2 2h7a2 2 0 0 0 2 -2v-2"></path>\
                                <path d="M9 12h12l-3 -3"></path>\
                                <path d="M18 15l3 -3"></path>\
                                </svg>',
                        href=f'/logout'),
                    ])



    @property
    def login_manager(self) -> LoginManager:
        """Expose LoginManager so plugin_manager can wire it into the Flask app.

        This satisfies the :class:`~funlab.core.plugin.ISecurityProvider`
        Protocol via structural (duck-type) matching — no inheritance from
        ``SecurityPlugin`` is needed.
        """
        return self._login_manager

    @property
    def entities_registry(self):
        """ FunlabFlask use to table creation by sqlalchemy in __init__ for application initiation """
        return entities_registry

    @property
    def oauths_info(self):
        return { oauth_name:value.get('provider') for (oauth_name, value) in self.oauths.items()}

    def get_oauth_register(self, oauth_name:str=None):
        if oauth_name is None:
            oauth_name = self.oauth_name_inuse
        return self.oauths.get(oauth_name).get('register')

    def get_userinfo_field_value(self, userinfo, fieldname):
        return userinfo[self.oauths.get(self.oauth_name_inuse).get('userinfo_key_mapping')[fieldname]]

    def _login_rate_limited(self, key: tuple, limit: int = 5, window: int = 60) -> bool:
        """回傳 True 表示已超過 limit 次/window 秒。

        記憶體滑窗（AUTH-05）：單程序部署足夠；多 worker 部署須換 app_cache/redis。
        鎖內禁止 DB/IO（紅線）。
        """
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



    def register_routes(self):
        @self.blueprint.route('/login', defaults={'style': None}, methods=['GET', 'POST'])
        @self.blueprint.route('/login/', defaults={'style': None}, methods=['GET', 'POST'])
        @self.blueprint.route('/login/<style>', methods=['GET', 'POST'])
        def login(style):
            login_form = LoginForm(request.form)
            if 'login' in request.form:
                email = request.form.get('email', '')
                password = request.form.get('password', '')
                # AUTH-05：/login 限流（per-IP + per-email 滑窗；單進程記憶體計數）
                if (self._login_rate_limited(('ip', request.remote_addr))
                        or self._login_rate_limited(('acct', email.strip().lower()))):
                    flash('Too many login attempts. Please wait a minute and try again.', 'warning')
                    return render_template('/sign-in.html', form=login_form, oauths_info=self.oauths_info), 429
                # checkbox 未勾選時瀏覽器不送此欄位，須用 .get
                rememberme = request.form.get('rememberme') == 'y'
                # Locate user
                # 注意：DB session 改名 sa_session，避免遮蔽 Flask session
                # （AUTH-08 的 session.clear() 必須作用於 Flask 簽名 cookie session）
                with self.app.dbmgr.session_context() as sa_session:
                    user = load_user(email, sa_session)
                    result = None if user is None else user.check_password_login(password)
                    if result == LOGIN_OK:
                        user.user_folder = self.app.get_user_data_storage_path(user.username)
                        session.clear()   # AUTH-08 登入手勢：丟棄匿名期 session，防固定/殘留
                        login_user(user, remember=rememberme)
                        # AUTH-09：next 僅跟本站相對路徑（經 _safe_next 白名單）
                        return redirect(_safe_next(request.args.get('next') or request.form.get('next')))
                    elif result == LOGIN_EXTERNAL_ACCOUNT:
                        # AUTH-06：OAuth 帳號非機密（頁面本就列出 provider），保留引導訊息
                        flash('Your account is from external authentication provider, please login with proper provider below.', "info")
                    elif result == LOGIN_INACTIVE:
                        flash("Account is not active. Please contact administrator.", "warning")
                    else:
                        # AUTH-06：不存在與錯密碼共用同一訊息，杜絕列舉
                        flash("Invalid email or password. Please try again.", "warning")
                return render_template('/sign-in.html', form=login_form, oauths_info=self.oauths_info)
            elif current_user and current_user.is_authenticated:
                return redirect(url_for('root_bp.home'))
            else:
                style = '-'+style if style else ''
                return render_template(f'/sign-in{style}.html', form=login_form, oauths_info=self.oauths_info)

        @self.blueprint.route('/oauth_login/<oauth_name>')
        def oauth_login(oauth_name):
            redirect_uri = url_for(f'{self.bp_name}.authorize', oauth_name=oauth_name, _external=True)
            try:
                self.mylogger.debug(f"OAuth login start for {oauth_name}, redirect_uri={redirect_uri}")
                session['_oauth_login_start'] = time.time()
            except Exception:
                pass
            return self.get_oauth_register(oauth_name).authorize_redirect(redirect_uri)

        @self.blueprint.route('/authorize/<oauth_name>')
        def authorize(oauth_name):
            start_all = time.time()
            try:
                self.mylogger.debug(f"Authorize callback start for {oauth_name}")
                t0 = time.time()
                token = self.get_oauth_register(oauth_name).authorize_access_token()
                self.mylogger.debug(f"authorize_access_token took {time.time()-t0:.3f}s, token_present={bool(token)}")
                if token is None:
                    msg = 'Access denied: reason={0} error={1}'.format(
                        request.args.get('error_reason', ''),
                        request.args.get('error_description', '')
                    )
                    self.mylogger.warning(f"OAuth access denied: {msg}")
                    flash(f'{msg}', category='danger')
                    return render_template('sign-in.html', form=LoginForm(), oauths_info=self.oauths_info)
            except Exception as e:
                # AUTH-14：例外細節只進 log，不回餽瀏覽器（探測面紅線）
                self.mylogger.exception("authorize_access_token exception")
                flash('OAuth sign-in failed. Please try again.', category='danger')
                return render_template('sign-in.html', form=LoginForm(), oauths_info=self.oauths_info)
            try:
                self.oauth_name_inuse = oauth_name
                t1 = time.time()
                userinfo = self.get_oauth_register(oauth_name).userinfo()
                self.mylogger.debug(f"userinfo() took {time.time()-t1:.3f}s; total authorize handler {time.time()-start_all:.3f}s")
                oauth_user = OAuthUser(email=self.get_userinfo_field_value(userinfo, 'email'),
                                       username=self.get_userinfo_field_value(userinfo, 'username'),
                                       avatar_url=self.get_userinfo_field_value(userinfo, 'avatar_url'),
                                       password=None,  state='active')
                with self.app.dbmgr.session_context() as sa_session:
                    if (user:=load_user(oauth_user.email, sa_session)):
                        user.user_folder = self.app.get_user_data_storage_path(user.username)
                        if user.merge_userdata(oauth_user):
                            save_user(user, sa_session)
                    else:
                        save_user(oauth_user.to_userentity(), sa_session)
                        user=load_user(oauth_user.email, sa_session)
                        user.user_folder = self.app.get_user_data_storage_path(user.username)
                # AUTH-08：清掉 _oauth_login_start 與匿名期殘留鍵。位置紅線：
                # 必須在 authorize_access_token()（已於上方完成 authlib state 校驗）
                # 之後、login_user() 之前——不可移到校驗之前。
                session.clear()
                # AUTH-14：access_token 不再明文存簽名 cookie（全 workspace
                # grep 無消費者）；如需 API 續用應改放 app.cache（server-side）
                session['oauth_login_at'] = int(time.time())
                if not login_user(user):
                    # AUTH-04(a)(5)：停用 OAuth 帳號給明確訊息而非困惑導向
                    flash("Account is not active. Please contact administrator.", "warning")
                    return render_template('sign-in.html', form=LoginForm(), oauths_info=self.oauths_info)
                return redirect(url_for('root_bp.home'))
            except Exception as e:
                self.oauth_name_inuse = None
                # AUTH-14：例外細節只進 log，不回餽瀏覽器
                self.mylogger.exception("authorize userinfo/userdata exception")
                flash('Get userinfo from OAuth provider failed. Please try again.', category='danger')
                return render_template('sign-in.html', form=LoginForm(), oauths_info=self.oauths_info)

        @self.blueprint.route('/logout', methods=['GET', 'POST'])
        @login_required
        def logout():
            # AUTH-07：GET 不再直接登出（防跨站 <img src=/logout> 強制登出）；
            # GET 顯示確認頁，POST（帶 CSRF token，由全域 CSRFProtect 強制）才登出。
            if request.method == 'GET':
                return render_template('logout.html')
            logout_user()
            session.pop('oauth_token', None)
            session.pop('user_id', None)
            return redirect(url_for('root_bp.index'))

        @self.blueprint.route('/register', methods=['GET', 'POST'])
        def register():
            from funlab.auth.user import EXTERNAL_AUTH_PLACEHOLDER
            # AUTH-02（Q3 裁示：ALLOW_REGISTER 預設 false＋邀請制）：
            # 需於 [AuthView] 明示 ALLOW_REGISTER=true 才開放註冊
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

        @self.blueprint.route('/resetpass', methods=['GET', 'POST'])
        @login_required
        def resetpass():
            # 只允許已登入使用者變更「自己的」密碼；OAuth 帳號不可設定密碼
            resetpass_form = ResetPassForm(request.form)
            if 'resetpass' in request.form:
                old_password = request.form.get('old_password', '')
                email = request.form.get('email', '')
                new_password = request.form.get('new_password', '')
                confirm_password = request.form.get('confirm_password', '')
                if email.strip().lower() != (current_user.email or '').lower():
                    flash('You can only change your own password.', category='danger')
                    return render_template('/resetpass.html', form=resetpass_form)
                if not new_password or new_password != confirm_password:
                    flash('New password not consistancy. Please re-enter.', category='warning')
                    return render_template('/resetpass.html', form=resetpass_form)
                with self.app.dbmgr.session_context() as sa_session:
                    user = load_user(current_user.id, sa_session)
                    if user is None:
                        flash('User not exist. Please check.', "warning")
                        return render_template('/resetpass.html', form=resetpass_form)
                    result = user.check_password_login(old_password)
                    if result == LOGIN_EXTERNAL_ACCOUNT:
                        flash('Your account is from external authentication provider; password cannot be set here.', category='info')
                        return render_template('/resetpass.html', form=resetpass_form)
                    if result != LOGIN_OK:
                        flash('Wrong password! Please check.', category='danger')
                        return render_template('/resetpass.html', form=resetpass_form)
                    user.user_folder = self.app.get_user_data_storage_path(user.username)
                    user.password = new_password
                    user.hash_pass()
                    save_user(user, sa_session)
                logout_user()
                flash('Password reset successfully. Please login again.', category='success')
                return render_template('/sign-in.html', form=LoginForm(), oauths_info=self.oauths_info)
            return render_template('/resetpass.html', form=resetpass_form)

        @self.blueprint.route('/settings')
        @login_required
        def settings():
            return render_template('settings.html')

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
                    # （注意：get_user_data_storage_path 會 mkdir，回 None 前不得呼叫）
                    return None
                user.user_folder = self.app.get_user_data_storage_path(user.username)
                return user

        @self.login_manager.request_loader
        def request_loader(request):
            # AUTH-04：OAuth Authorization 分支＝「把 provider 當 IdP 複驗」。
            # 本地先剝 Bearer 前綴並做最小格式檢查；一切以 provider 回應為準，
            # 任何失敗一律回 None（走 unauthorized 流程），絕不把例外升格成 500。
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
                # deprecation: ?google_token= 讓 token 進 URL/日誌，新串流請用 Authorization header
                token = request.headers.get('Authorization') or request.args.get('google_token')
                if not token:
                    return None
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

