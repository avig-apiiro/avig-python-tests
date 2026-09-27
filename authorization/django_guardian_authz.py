"""Per-object permissions with django-guardian."""
from guardian.shortcuts import assign_perm, get_objects_for_user, remove_perm

VIEW_DOCUMENT = "documents.view_document"
CHANGE_DOCUMENT = "documents.change_document"


def share_document(document, user, can_edit: bool = False) -> None:
    assign_perm("view_document", user, document)
    if can_edit:
        assign_perm("change_document", user, document)


def unshare_document(document, user) -> None:
    remove_perm("view_document", user, document)
    remove_perm("change_document", user, document)


def visible_documents(user):
    return get_objects_for_user(user, VIEW_DOCUMENT)


def can_edit(user, document) -> bool:
    return user.has_perm(CHANGE_DOCUMENT, document)
