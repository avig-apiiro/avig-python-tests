"""Session-cookie authentication with Flask-Login."""
from flask_login import LoginManager, UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

login_manager = LoginManager()


class User(UserMixin):
    def __init__(self, user_id: str, username: str, password_hash: str):
        self.id = user_id
        self.username = username
        self.password_hash = password_hash


_USERS = {
    "1": User("1", "alice", generate_password_hash("alice-password")),
}


@login_manager.user_loader
def load_user(user_id: str):
    return _USERS.get(user_id)


def authenticate(username: str, password: str):
    for user in _USERS.values():
        if user.username == username and check_password_hash(user.password_hash, password):
            return user
    return None
