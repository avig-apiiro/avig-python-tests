"""Implementation style 1 of the Vertigo service: SUBCLASS the generated
VertigoServicer base class.

This is the idiomatic, forward-compatible way. If a new RPC is added to the
proto, the inherited base-class method supplies a default that responds with
grpc.StatusCode.UNIMPLEMENTED, so this class keeps working without changes.
(Analogous to embedding UnimplementedXxxServer in Go.)
"""

import vertigo_pb2
import vertigo_pb2_grpc


class One(vertigo_pb2_grpc.VertigoServicer):
    def One(self, request, context):
        return vertigo_pb2.OneResponse(
            message="We're one, but we're not the same: " + request.singer,
        )

    def Pride(self, request, context):
        return vertigo_pb2.PrideResponse(
            message="One man come in the name of love: " + request.name,
        )
