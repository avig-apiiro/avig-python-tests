"""Implementation of the Desire service."""

import desire_pb2
import desire_pb2_grpc


class Gloria(desire_pb2_grpc.DesireServicer):
    def Gloria(self, request, context):
        return desire_pb2.GloriaResponse(
            message="Gloria, in te domine: " + request.caller,
        )

    def Bad(self, request, context):
        return desire_pb2.BadResponse(
            message="If I could through myself, set your spirit free: " + request.mood,
        )
