"""U2-themed gRPC service implementations.

Layout / convention for this repo:
  proto/*.proto        service + message definitions
  *_pb2.py             generated messages (grpc_tools.protoc, flat top-level)
  *_pb2_grpc.py        generated gRPC stubs / servicer base classes
  u2/*.py              hand-written service implementations
  proto/pride.sh       regenerates the *_pb2 modules
"""
