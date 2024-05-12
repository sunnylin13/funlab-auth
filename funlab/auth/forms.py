from flask_wtf import FlaskForm
from wtforms import (BooleanField,  PasswordField, StringField, SubmitField)
from wtforms.validators import DataRequired, Email

class LoginForm(FlaskForm):
    email = StringField('Email', id='email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', id='password', validators=[DataRequired()])
    rememberme = BooleanField('Remember Me', id='rememberme', default=True)

class AddUserForm(FlaskForm):
    username = StringField('Username', id='username_create', validators=[DataRequired()])
    email = StringField('Email', id='email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', id='password', validators=[DataRequired()])

class ResetPassForm(FlaskForm):
    old_password = PasswordField('Old Password', id='old_password', validators=[DataRequired()])
    new_password = PasswordField('New Password', id='new_password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', id='confirm_password', validators=[DataRequired()])
    resetpass = SubmitField('Reset Password')

class UserSettingForm(FlaskForm):
    username = StringField('Username', id='username_create', validators=[DataRequired()])
    avatar_url = StringField('Avatar', id='avatar_url')


