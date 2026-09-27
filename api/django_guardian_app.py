import json

from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.urls import path
from django.views.decorators.http import require_GET, require_POST
from guardian.decorators import permission_required_or_403

from api.documents.models import Document
from authorization.django_guardian_authz import VIEW_DOCUMENT, can_edit, share_document, visible_documents


@require_GET
@login_required
def list_documents(request):
    return JsonResponse({"documents": list(visible_documents(request.user).values("id", "title"))})


@require_GET
@login_required
@permission_required_or_403(VIEW_DOCUMENT, (Document, "pk", "pk"))
def get_document(request, pk: int):
    document = get_object_or_404(Document, pk=pk)
    return JsonResponse({"id": document.pk, "title": document.title, "body": document.body})


@require_POST
@login_required
def share(request, pk: int):
    document = get_object_or_404(Document, pk=pk)
    if not can_edit(request.user, document):
        return JsonResponse({"error": "forbidden"}, status=403)
    body = json.loads(request.body or "{}")
    target = get_object_or_404(get_user_model(), username=body.get("username"))
    share_document(document, target, can_edit=bool(body.get("can_edit")))
    return JsonResponse({"shared_with": target.username})


urlpatterns = [
    path("documents", list_documents),
    path("documents/<int:pk>", get_document),
    path("documents/<int:pk>/share", share),
]
