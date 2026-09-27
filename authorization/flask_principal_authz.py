"""Role-based authorization with Flask-Principal."""
from flask import Flask
from flask_principal import Identity, Permission, Principal, RoleNeed, UserNeed, identity_loaded

from authentication.flask_httpauth_auth import basic_auth

_ROLES = {"alice": ["reader"], "bob": ["reader", "admin"]}

principal = Principal(use_sessions=False)
reader_permission = Permission(RoleNeed("reader"))
admin_permission = Permission(RoleNeed("admin"))


@principal.identity_loader
def load_identity_from_basic_auth():
    username = basic_auth.current_user()
    if username:
        return Identity(username)
    return None


def init_principal(app: Flask) -> None:
    principal.init_app(app)

    @identity_loaded.connect_via(app)
    def on_identity_loaded(sender, identity):
        identity.provides.add(UserNeed(identity.id))
        for role in _ROLES.get(identity.id, []):
            identity.provides.add(RoleNeed(role))
