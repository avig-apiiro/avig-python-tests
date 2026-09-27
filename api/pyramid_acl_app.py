from wsgiref.simple_server import make_server

from pyramid.config import Configurator
from pyramid.httpexceptions import HTTPNotFound
from pyramid.view import view_config

from authorization.pyramid_acl import BasicAuthACLSecurityPolicy, Report, ReportsRoot

_REPORTS = {"r1": Report("r1", owner="alice"), "r2": Report("r2", owner="bob")}


def report_factory(request):
    report = _REPORTS.get(request.matchdict["report_id"])
    if report is None:
        raise HTTPNotFound()
    return report


@view_config(route_name="reports", renderer="json", permission="view")
def list_reports(request):
    return {"reports": list(_REPORTS)}


@view_config(route_name="report", renderer="json", permission="view", request_method="GET")
def get_report(context, request):
    return {"id": context.id, "owner": context.owner}


@view_config(route_name="report", renderer="json", permission="edit", request_method="PUT")
def update_report(context, request):
    return {"id": context.id, "updated_by": request.authenticated_userid}


def create_app():
    with Configurator(root_factory=ReportsRoot) as config:
        config.set_security_policy(BasicAuthACLSecurityPolicy())
        config.add_route("reports", "/reports")
        config.add_route("report", "/reports/{report_id}", factory=report_factory)
        config.scan()
        return config.make_wsgi_app()


if __name__ == "__main__":
    make_server("127.0.0.1", 6543, create_app()).serve_forever()
