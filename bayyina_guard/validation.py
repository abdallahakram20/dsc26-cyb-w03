"""Upload validation for Bayyina contracts. Rules: README.md, "What to build", part 1."""
from __future__ import annotations

import re
import unicodedata
import uuid
from dataclasses import dataclass

MAX_BYTES = 25 * 1024 * 1024

_PDF_TYPE = "application/pdf"
_DOCX_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
_CANONICAL = {"pdf": _PDF_TYPE, "docx": _DOCX_TYPE}
_MAGIC = {"pdf": b"%PDF-", "docx": b"PK\x03\x04"}
_BIDI = {0x061C, 0x200E, 0x200F} | set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
_MATTER_RE = re.compile(r"MAT-[0-9]{4}-[0-9]{5}")


class ValidationError(Exception):
    def __init__(self, errors: dict[str, str]):
        super().__init__(", ".join(sorted(errors)))
        self.errors = errors          # field name -> message; keys from: filename, content_type,
                                      # size_bytes, matter_id, first_bytes


@dataclass(frozen=True)
class CleanUpload:
    stored_name: str      # "<32 hex chars>.<ext>", generated, never derived from the filename
    display_name: str     # the filename after NFC normalisation
    extension: str        # "pdf" or "docx", lowercase
    content_type: str
    size_bytes: int
    matter_id: str


def validate_upload(meta: dict) -> CleanUpload:
    """Check every field of `meta` and raise one ValidationError listing all failing fields."""
    if not isinstance(meta, dict):
        raise ValidationError({
            "filename": "meta must be a dict",
            "content_type": "meta must be a dict",
            "size_bytes": "meta must be a dict",
            "matter_id": "meta must be a dict",
            "first_bytes": "meta must be a dict",
        })

    errors: dict[str, str] = {}

    # ---- filename ----
    raw_filename = meta.get("filename")
    filename_invalid = False
    extension = None
    display_name = None
    if not isinstance(raw_filename, str):
        errors["filename"] = "filename must be a string"
        filename_invalid = True
    else:
        name = unicodedata.normalize("NFC", raw_filename)
        display_name = name
        if not 1 <= len(name) <= 120:
            errors["filename"] = "filename must be 1-120 characters after NFC normalisation"
            filename_invalid = True
        elif any(unicodedata.category(ch) == "Cc" for ch in name):
            errors["filename"] = "filename must not contain control characters"
            filename_invalid = True
        elif any(ord(ch) in _BIDI for ch in name):
            errors["filename"] = "filename must not contain bidi control characters"
            filename_invalid = True
        elif "/" in name or "\\" in name or ".." in name:
            errors["filename"] = "filename must not contain a path separator or '..'"
            filename_invalid = True
        elif name.startswith("."):
            errors["filename"] = "filename must not start with '.'"
            filename_invalid = True
        elif "." not in name:
            errors["filename"] = "filename must have a pdf or docx extension"
            filename_invalid = True
        else:
            stem, ext = name.rsplit(".", 1)
            ext = ext.lower()
            if ext not in _CANONICAL or not stem.strip():
                errors["filename"] = "filename must end in .pdf or .docx with a non-blank name"
                filename_invalid = True
            else:
                extension = ext

    # ---- content_type ----
    content_type = meta.get("content_type")
    if filename_invalid:
        if not isinstance(content_type, str):
            errors["content_type"] = "content_type must be a string"
    elif extension is not None:
        if content_type != _CANONICAL[extension]:
            errors["content_type"] = "content_type must match the filename extension"

    # ---- first_bytes ----
    first_bytes = meta.get("first_bytes")
    if filename_invalid:
        if not isinstance(first_bytes, bytes):
            errors["first_bytes"] = "first_bytes must be bytes"
    elif extension is not None:
        if not isinstance(first_bytes, bytes):
            errors["first_bytes"] = "first_bytes must be bytes"
        elif not first_bytes.startswith(_MAGIC[extension]):
            errors["first_bytes"] = "first_bytes must match the filename extension"

    # ---- size_bytes ----
    size_bytes = meta.get("size_bytes")
    if type(size_bytes) is not int:  # type() check rejects bool and float explicitly
        errors["size_bytes"] = "size_bytes must be an int"
    elif not 1 <= size_bytes <= MAX_BYTES:
        errors["size_bytes"] = "size_bytes must be between 1 and MAX_BYTES inclusive"

    # ---- matter_id ----
    matter_id = meta.get("matter_id")
    if not isinstance(matter_id, str) or not matter_id.isascii():
        errors["matter_id"] = "matter_id must be ASCII"
    elif _MATTER_RE.fullmatch(matter_id) is None:
        errors["matter_id"] = "matter_id must be MAT- + 4 digits + - + 5 digits"

    if errors:
        raise ValidationError(errors)

    assert extension is not None and display_name is not None
    return CleanUpload(
        stored_name=f"{uuid.uuid4().hex}.{extension}",
        display_name=display_name,
        extension=extension,
        content_type=_CANONICAL[extension],
        size_bytes=size_bytes,
        matter_id=matter_id,
    )
