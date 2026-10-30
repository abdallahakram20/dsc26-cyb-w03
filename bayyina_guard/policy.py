"""Document access policy for Bayyina. Rules: README.md, "What to build", part 2."""
from __future__ import annotations

from dataclasses import dataclass, field

_ROLES = {
    "partner": {"read", "comment", "upload_version", "delete", "share_external"},
    "associate": {"read", "comment", "upload_version"},
    "paralegal": {"read", "upload_version"},
    "client": {"read", "comment"},
    "auditor": set(),
}
_ACTIONS = {"read", "comment", "upload_version", "delete", "share_external"}


@dataclass(frozen=True)
class User:
    id: str
    role: str
    client_id: str | None = None
    matters: frozenset[str] = field(default_factory=frozenset)
    mfa: bool = False


@dataclass(frozen=True)
class Document:
    id: str
    client_id: str
    matter_id: str
    confidentiality: str = "normal"
    legal_hold: bool = False


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def authorize(user: User | None, action: str, doc: Document) -> Decision:
    """Evaluate the nine rules in order and return the first denial, else Decision(True, "ok")."""
    if user is None or not user.id:
        return Decision(False, "unauthenticated")
    if action not in _ACTIONS:
        return Decision(False, "unknown_action")
    if user.role not in _ROLES:
        return Decision(False, "unknown_role")
    if action == "delete" and doc.legal_hold:
        return Decision(False, "legal_hold")
    if action not in _ROLES[user.role]:
        return Decision(False, "role_not_permitted")
    if user.role == "client" and (user.client_id is None or user.client_id != doc.client_id):
        return Decision(False, "tenant_mismatch")
    if user.role in ("associate", "paralegal") and doc.matter_id not in (user.matters or frozenset()):
        return Decision(False, "not_assigned")
    if user.role in ("client", "paralegal") and doc.confidentiality != "normal":
        return Decision(False, "restricted")
    if (doc.confidentiality != "normal" or action == "share_external") and user.mfa is not True:
        return Decision(False, "mfa_required")
    return Decision(True, "ok")


def visible_documents(user: User | None, docs: list[Document]) -> list[Document]:
    """The documents `user` may read, in their original order."""
    return [doc for doc in docs if authorize(user, "read", doc).allowed]
