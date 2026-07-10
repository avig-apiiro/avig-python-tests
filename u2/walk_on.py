"""Implementation style 2 of the SAME Vertigo service: a plain class that does
NOT inherit VertigoServicer.

grpc's add_VertigoServicer_to_server() only looks up the servicer's methods by
name, so inheritance is not required -- a duck-typed class works too. The
trade-off is that there is no inherited default for RPCs this class forgets to
implement (adding a new RPC to the proto silently drops it unless added here).
(Analogous to implementing the Go interface directly, without embedding
UnimplementedXxxServer.)
"""

import vertigo_pb2


class WalkOn:
    def One(self, request, context):
        return vertigo_pb2.OneResponse(
            message="Walk on: " + request.singer,
        )

    def Pride(self, request, context):
        return vertigo_pb2.PrideResponse(
            message="Pride, in the name of love: " + request.name,
        )
