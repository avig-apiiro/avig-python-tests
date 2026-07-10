"""Server wiring for the U2 gRPC services, plus a small HTTP gateway.

Two things are exposed here:

  * build_grpc_servers() registers every servicer on gRPC servers, at the usual
    /<package>.<Service>/<Method> routes. The Vertigo service has TWO
    implementations (One and WalkOn); only one servicer can own a service on a
    single server, so they are registered on separate servers -- mirroring the
    two implementation styles.

  * build_http_routes()/U2Gateway serve the BeautifulDay service over plain
    HTTP at the fully custom paths declared in the proto's google.api.http
    options (all under /u2). The route table is read from the proto descriptor
    at runtime, so the paths come entirely from the options -- nothing here
    hardcodes "/u2/...".

The stdlib http.server is used on purpose: the repo has a top-level flask.py
that would shadow the real Flask package, so importing flask here is avoided.
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

import grpc
from google.api import annotations_pb2

import beautiful_day_pb2
import beautiful_day_pb2_grpc
import desire_pb2_grpc
import vertigo_pb2_grpc

from .elevation import Elevation
from .gloria import Gloria
from .one import One
from .walk_on import WalkOn


def build_grpc_servers():
    """Register the servicers and return (primary, alternate) gRPC servers."""
    primary = grpc.server(_NullExecutor())
    vertigo_pb2_grpc.add_VertigoServicer_to_server(One(), primary)
    desire_pb2_grpc.add_DesireServicer_to_server(Gloria(), primary)
    beautiful_day_pb2_grpc.add_BeautifulDayServicer_to_server(Elevation(), primary)

    # The alternate Vertigo implementation (duck-typed) on its own server.
    alternate = grpc.server(_NullExecutor())
    vertigo_pb2_grpc.add_VertigoServicer_to_server(WalkOn(), alternate)

    return primary, alternate


def build_http_routes():
    """Read the google.api.http options off the BeautifulDay descriptor and
    return {(http_method, path): rpc_method_name}. The paths are taken straight
    from the proto options -- they are not hardcoded here."""
    routes = {}
    service = beautiful_day_pb2.DESCRIPTOR.services_by_name["BeautifulDay"]
    for method in service.methods:
        rule = method.GetOptions().Extensions[annotations_pb2.http]
        if rule.get:
            routes[("GET", rule.get)] = method.name
        elif rule.post:
            routes[("POST", rule.post)] = method.name
        elif rule.put:
            routes[("PUT", rule.put)] = method.name
        elif rule.delete:
            routes[("DELETE", rule.delete)] = method.name
    return routes


class U2Gateway(BaseHTTPRequestHandler):
    """Maps the option-defined /u2/... HTTP routes onto the Elevation servicer."""

    routes = build_http_routes()
    servicer = Elevation()

    def _dispatch(self, http_method):
        rpc_name = self.routes.get((http_method, self.path))
        if rpc_name is None:
            self.send_error(404)
            return
        # For brevity the request body is not parsed into the proto message; a
        # real gateway would transcode JSON <-> protobuf here.
        request_cls = getattr(beautiful_day_pb2, rpc_name + "Request")
        response = getattr(self.servicer, rpc_name)(request_cls(), None)
        body = json.dumps({"message": response.message}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")


def serve_http(port=8080):
    return HTTPServer(("localhost", port), U2Gateway)


class _NullExecutor:
    """Minimal executor so grpc.server() can be constructed without spinning up
    a real thread pool (this module is used as parseable test data, not run)."""

    def submit(self, fn, *args, **kwargs):
        raise NotImplementedError

    def shutdown(self, wait=True):
        pass
