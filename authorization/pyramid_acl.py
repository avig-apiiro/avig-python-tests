"""ACL-based authorization with a Pyramid security policy (HTTP Basic identity)."""
from pyramid.authentication import extract_http_basic_credentials
from pyramid.authorization import ACLHelper, Allow, Authenticated, Everyone
from werkzeug.security import check_password_hash, generate_password_hash

_USERS = {
    "alice": {"password_hash": generate_password_hash("alice-password"), "groups": ["group:readers"]},
    "bob": {"password_hash": generate_password_hash("bob-password"), "groups": ["group:readers", "group:editors"]},
}


class ReportsRoot:
    __acl__ = [
        (Allow, Authenticated, "view"),
        (Allow, "group:editors", "edit"),
    ]

    def __init__(self, request):
        self.request = request


class Report:
    def __init__(self, report_id: str, owner: str):
        self.id = report_id
        self.owner = owner
        self.__acl__ = [
            (Allow, f"user:{owner}", "view"),
            (Allow, f"user:{owner}", "edit"),
            (Allow, "group:editors", "view"),
        ]


class BasicAuthACLSecurityPolicy:
    def __init__(self):
        self.acl = ACLHelper()

    def identity(self, request):
        creds = extract_http_basic_credentials(request)
        if creds is None:
            return None
        user = _USERS.get(creds.username)
        if user and check_password_hash(user["password_hash"], creds.password):
            return {"userid": creds.username, "groups": user["groups"]}
        return None

    def authenticated_userid(self, request):
        identity = request.identity
        return identity["userid"] if identity else None

    def permits(self, request, context, permission):
        principals = [Everyone]
        identity = request.identity
        if identity:
            principals += [Authenticated, f"user:{identity['userid']}", *identity["groups"]]
        return self.acl.permits(context, principals, permission)

    def remember(self, request, userid, **kw):
        return []

    def forget(self, request, **kw):
        return []
