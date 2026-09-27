from django.urls import include, path
from rest_framework import viewsets
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.routers import DefaultRouter

from api.documents.models import Document
from api.documents.serializers import DocumentSerializer
from authentication.drf_token_auth import BearerTokenAuthentication
from authorization.drf_object_permissions import IsOwnerOrReadOnly


class DocumentViewSet(viewsets.ModelViewSet):
    serializer_class = DocumentSerializer
    authentication_classes = [BearerTokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated, IsOwnerOrReadOnly]
    queryset = Document.objects.all()

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)


router = DefaultRouter()
router.register("documents", DocumentViewSet, basename="owner-documents")

urlpatterns = [
    path("", include(router.urls)),
]
