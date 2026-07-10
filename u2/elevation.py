"""Implementation of the BeautifulDay service.

Its gRPC routes are the usual /u2.beautifulday.v1.BeautifulDay/<Method>, but
when served through the HTTP gateway (see where_the_streets_have_no_name.py) the
same methods are reachable at the fully custom paths declared in the proto's
google.api.http options: GET /u2/beautiful-day and POST /u2/with-or-without-you.
"""

import beautiful_day_pb2
import beautiful_day_pb2_grpc


class Elevation(beautiful_day_pb2_grpc.BeautifulDayServicer):
    def Elevation(self, request, context):
        return beautiful_day_pb2.ElevationResponse(
            message="It's a beautiful day, don't let it get away: " + request.mood,
        )

    def WithOrWithoutYou(self, request, context):
        return beautiful_day_pb2.WithOrWithoutYouResponse(
            message="I can't live, with or without you: " + request.partner,
        )
