
import copy
from typing import Type
from authlib.integrations.flask_client import OAuth
from flask import (flash, redirect, render_template, request,
                    session, url_for)
from flask_login import current_user, login_required, login_user, logout_user


from funlab.core.menu import MenuDivider, MenuItem
from funlab.core.plugin import SecurityPlugin
from funlab.core.config import Config

from .forms import AddUserForm, LoginForm, ResetPassForm
from .user import OAuthUser, UserEntity, entities_registry
from funlab.core.appbase import _FlaskBase
from sqlalchemy.orm import Session, with_polymorphic
from sqlalchemy import select, or_

class AuthView(SecurityPlugin):
    @staticmethod
    def load_users(id_email, sa_session:Session)->Type[UserEntity]:
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
        User = with_polymorphic(UserEntity, '*')
        stmt = select(User).where(or_(User.id == id_email, User.email == id_email, ))
        user = sa_session.execute(stmt).scalar()
        return user

    @staticmethod
    def save_user(user:Type[UserEntity], sa_session:Session):  # Type[UserEntity] means user should be an instance of UserEntity or any of its subclasses
        sa_session.merge(user)
        sa_session.commit()

    def __init__(self, app:_FlaskBase):
        super().__init__(app, url_prefix="")
        # Apply flask-caching memoize decorator to load_user
        # AuthView.load_user = self.app.cache.memoize()(AuthView.load_user)
        oauth = OAuth(app)
        oauth_configs:Config = self.plugin_config
        self.oauths:dict[str:dict] = {}
        default_userinfo_keys = {'email':'email', 'username':'username', 'avatar_url':'avatar_url'}
        try:
            for oauth_name in oauth_configs.keys(): #  oauth_names:
                oauth_cfg = oauth_configs.get(oauth_name)
                provider = oauth_cfg.pop('provider')
                userinfo_key_mapping =  copy.copy(default_userinfo_keys)
                userinfo_key_mapping.update(oauth_cfg.pop('userinfo_key_mapping', {}))
                oauth_register = oauth.register(name=oauth_name, **oauth_cfg)
                self.oauths.update({oauth_name: {'provider':provider, 'register':oauth_register, 'userinfo_key_mapping':userinfo_key_mapping}})
        except Exception as e:
            msg = f'{oauth_name} OAuth register fail, please check config:{oauth_cfg}'
            raise e from Exception(msg)
        self.oauth_name_inuse:str = None
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

        self.register_routes()
        self.register_login_handler()

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

    def register_routes(self):
        @self.blueprint.route('/login', defaults={'style': None}, methods=['GET', 'POST'])
        @self.blueprint.route('/login/', defaults={'style': None}, methods=['GET', 'POST'])
        @self.blueprint.route('/login/<style>', methods=['GET', 'POST'])
        def login(style):
            login_form = LoginForm(request.form)
            if 'login' in request.form:
                email = request.form['email']
                password = request.form['password']
                rememberme = request.form['rememberme']
                # Locate user
                sa_session = self.app.dbmgr.get_db_session()
                user = AuthView.load_users(email, sa_session)
                if user: # and user.verify_pass(password):
                    login_user(user, remember=(rememberme=='y'))
                    return redirect(url_for('root_bp.home'))
                elif not user:
                    flash('User email not exist. Please check.', "warning")
                elif user.verify_pass('account+is+from+external+authentication+provider!!!'):
                    flash('Your account is from external authentication provider, please login with proper provider below.', "info")
                else:
                    flash("Incorrect password. Please try again.", "warning")
                return render_template('/sign-in.html', form=login_form, oauths_info=self.oauths_info)
            elif current_user and current_user.is_authenticated:
                return redirect(url_for('root_bp.home'))
            else:
                style = '-'+style if style else ''
                return render_template(f'/sign-in{style}.html', form=login_form, oauths_info=self.oauths_info)

        @self.blueprint.route('/oauth_login/<oauth_name>')
        def oauth_login(oauth_name):
            redirect_uri = url_for(f'{self.bp_name}.authorize', oauth_name=oauth_name, _external=True)
            return self.get_oauth_register(oauth_name).authorize_redirect(redirect_uri)

        @self.blueprint.route('/authorize/<oauth_name>')
        def authorize(oauth_name):
            try:
                token = self.get_oauth_register(oauth_name).authorize_access_token()
                if token is None:
                    msg = 'Access denied: reason={0} error={1}'.format(
                        request.args['error_reason'],
                        request.args['error_description']
                    )
                    flash(f'{msg}', category='danger')
                    return render_template('sign-in.html', form=LoginForm(), oauths_info=self.oauths_info)
            except Exception as e:
                flash(f'Exception:{str(e)}', category='danger')
                return render_template('sign-in.html', form=LoginForm(), oauths_info=self.oauths_info)
            try:
                self.oauth_name_inuse = oauth_name
                userinfo = self.get_oauth_register(oauth_name).userinfo()
                oauth_user = OAuthUser(email=self.get_userinfo_field_value(userinfo, 'email'),
                                       username=self.get_userinfo_field_value(userinfo, 'username'),
                                       avatar_url=self.get_userinfo_field_value(userinfo, 'avatar_url'),
                                       password=None,  state='active')
                sa_session = self.app.dbmgr.get_db_session()
                if (user:=AuthView.load_users(oauth_user.email, sa_session)):
                    if user.merge_userdata(oauth_user):
                        AuthView.save_user(user, sa_session)
                else:
                    AuthView.save_user(oauth_user.to_userentity(), sa_session)
                    user=AuthView.load_users(oauth_user.email, sa_session)
                session['oauth_token'] = token
                login_user(user)
                return redirect(url_for('root_bp.home'))
            except Exception as e:
                self.oauth_name_inuse = None
                flash(f'Get userinfo from OAuth provider failed. Exception:{e}', category='danger')
                return render_template('sign-in.html', form=LoginForm(), oauths_info=self.oauths_info)

        @self.blueprint.route('/logout')
        @login_required
        def logout():
            logout_user()
            session.pop('oauth_token', None)
            session.pop('user_id', None)
            return redirect(url_for('root_bp.index'))

        @self.blueprint.route('/register', methods=['GET', 'POST'])
        def register():
            create_account_form = AddUserForm(request.form)
            if 'register' in request.form:
                username = request.form['username']
                email = request.form['email']
                password = request.form['password']
                sa_session = self.app.dbmgr.get_db_session()
                user = AuthView.load_users(email, sa_session)
                if user:
                    flash('Email already registered. Check it and register again.', category='warning')
                    return render_template('/register.html', form=create_account_form)
                else:
                    user = UserEntity(username=username, email=email, password=password, avatar_url='', state='active')
                    sa_session = self.app.dbmgr.get_db_session()
                    sa_session.add(user)
                    sa_session.commit()
                    logout_user()
                    flash("Account is created successfully. Please login.", category='success')
                    return render_template('sign-in.html', form=LoginForm(), oauths_info=self.oauths_info)
            else:
                return render_template('/register.html', form=create_account_form)

        @self.blueprint.route('/resetpass', methods=['GET', 'POST'])
        def resetpass():
            resetpass_form = ResetPassForm(request.form)
            if 'resetpass' in request.form:
                old_password = request.form['old_password']
                email = request.form['email']
                new_password = request.form['new_password']
                confirm_password = request.form['confirm_password']
                if new_password != confirm_password:
                    flash('New password not consistancy. Please re-enter.', category='warning')
                    return render_template('/resetpass.html', form=resetpass_form)
                sa_session = self.app.dbmgr.get_db_session()
                user = AuthView.load_users(email, sa_session)
                if user and (user.verify_pass(old_password) or user.verify_pass('account+is+from+external+authentication+provider!!!')):
                    # sa_session = current_app.dbmgr.get_db_session()
                    user.password = new_password
                    user.hash_pass()
                    AuthView.save_user(user, sa_session)
                    # sa_session.merge(user)
                    # sa_session.commit()
                    flash('Password reset successfully. Please login again.', category='success')
                    return render_template('/sign-in.html', form=LoginForm(), oauths_info=self.oauths_info)
                elif user is not None:
                    flash('Wrong password! Please check.', category='danger')
                    return render_template('/resetpass.html', form=resetpass_form)
                elif user is None:
                    flash('User email not exist. Please check.', "warning")
                    return render_template('/resetpass.html', form=resetpass_form)
            else:
                return render_template('/resetpass.html', form=resetpass_form)

        @self.blueprint.route('/settings')
        @login_required
        def settings():
            return render_template('settings.html')

    def register_login_handler(self):
        @self.login_manager.unauthorized_handler
        def unauthorized_handler():
            return render_template('error-403.html'), 403

        @self.login_manager.user_loader
        def user_loader(id):
            return AuthView.load_users(id, self.app.dbmgr.get_db_session())

        @self.login_manager.request_loader
        def request_loader(request):
            sa_session = self.app.dbmgr.get_db_session()
            if 'user_id' in session:
                return AuthView.load_users(session['user_id'], sa_session)
            elif self.oauth_name_inuse and (oauth_register:=self.get_oauth_register()):
                if (token:=request.headers.get('Authorization')):
                    oauth_register.token = token
                elif (token:=request.args.get('google_token')):
                    oauth_register.token = token

                if oauth_register.token:
                    try:
                        userinfo = oauth_register.userinfo()
                        user = AuthView.load_users(self.get_userinfo_field_value(userinfo, 'email'), sa_session)
                        return user
                    except Exception as e:
                        raise Exception("Oauth request_loader for oauth_register.userinfo() failed! Check") from e
            return None

