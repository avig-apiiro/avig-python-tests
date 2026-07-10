#!/usr/bin/env bash
# Regenerates the Python gRPC code for the U2 services.
#
# Convention used in this repo:
#   proto/*.proto     service + message definitions
#   *_pb2.py          generated messages (flat, top-level, matching the repo)
#   *_pb2_grpc.py     generated gRPC stubs + servicer base classes
#   u2/*.py           hand-written service implementations
#
# Prerequisites (installed into the project venv):
#   python -m venv .venv
#   .venv/bin/pip install grpcio grpcio-tools googleapis-common-protos
#
# Run from the repository root: bash proto/pride.sh
set -euo pipefail

PY=${PY:-.venv/bin/python}

# vertigo.proto and desire.proto are plain gRPC services.
"$PY" -m grpc_tools.protoc -I proto \
  --python_out=. --grpc_python_out=. \
  proto/vertigo.proto proto/desire.proto

# beautiful_day.proto uses google.api.http annotations to define fully custom
# REST routes (all under /u2). The annotation protos are vendored under
# third_party/ so protoc can resolve the import without a network fetch.
"$PY" -m grpc_tools.protoc -I proto -I third_party \
  --python_out=. --grpc_python_out=. \
  proto/beautiful_day.proto
