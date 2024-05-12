
from functools import wraps
from flask_login import current_user
from flask import render_template
def role_required(roles:list|tuple):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if current_user.role not in roles:
                # Redirect to an unauthorized page or show an error message
                return render_template('error-403.html'), 403
            # Call the protected route handler function
            return func(*args, **kwargs)
        return wrapper
    return decorator

def admin_required():
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_admin:
                # Redirect to an unauthorized page or show an error message
                return render_template('error-403.html'), 403
            # Call the protected route handler function
            return func(*args, **kwargs)
        return wrapper

    return decorator