"""Generate JSON Schema (and TypeScript types) from the dataclass contract.

Why: the frontend team must not hand-write types that drift from the backend.
Run this after any schema change and commit the output.

    python -m schema.jsonschema

Writes:
    schema/generated/<Model>.schema.json   one file per top-level model
    web/src/types/schema.ts                TypeScript interfaces for the UI

Stdlib only (ADR-0009).
"""

from __future__ import annotations

import json
import types
import typing
from dataclasses import MISSING, fields, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from . import models

_NONE_TYPE = type(None)

#: Models that get their own schema file. Nested types are inlined via $defs.
TOP_LEVEL = ["Report", "MailSession", "Finding", "FeatureVector", "Capture"]


# --------------------------------------------------------------------------- #
# JSON Schema
# --------------------------------------------------------------------------- #


def _unwrap(annotation: Any) -> tuple[Any, bool]:
    origin = typing.get_origin(annotation)
    if origin is typing.Union or origin is types.UnionType:
        args = [a for a in typing.get_args(annotation) if a is not _NONE_TYPE]
        if len(args) == 1:
            return args[0], True
        return Any, True
    return annotation, False


def _schema_for(annotation: Any, defs: dict[str, Any]) -> dict[str, Any]:
    annotation, optional = _unwrap(annotation)
    node = _schema_for_concrete(annotation, defs)
    if optional:
        # Represent optionality as a nullable union, which TypeScript and most
        # validators handle cleanly.
        return {"anyOf": [node, {"type": "null"}]}
    return node


def _schema_for_concrete(annotation: Any, defs: dict[str, Any]) -> dict[str, Any]:
    if annotation is Any:
        return {}

    origin = typing.get_origin(annotation)
    if origin in (list, tuple):
        args = typing.get_args(annotation) or (Any,)
        return {"type": "array", "items": _schema_for(args[0], defs)}
    if origin is dict:
        args = typing.get_args(annotation)
        value = args[1] if len(args) == 2 else Any
        return {"type": "object", "additionalProperties": _schema_for(value, defs)}

    if isinstance(annotation, type):
        if is_dataclass(annotation):
            name = annotation.__name__
            if name not in defs:
                defs[name] = {}  # placeholder guards against recursion
                defs[name] = _object_schema(annotation, defs)
            return {"$ref": f"#/$defs/{name}"}
        if issubclass(annotation, Enum):
            name = annotation.__name__
            if name not in defs:
                defs[name] = {
                    "type": "string",
                    "enum": [member.value for member in annotation],
                    "description": (annotation.__doc__ or "").strip().split("\n")[0],
                }
            return {"$ref": f"#/$defs/{name}"}
        if annotation is datetime:
            return {"type": "string", "format": "date-time"}
        if annotation is bool:
            return {"type": "boolean"}
        if annotation is int:
            return {"type": "integer"}
        if annotation is float:
            return {"type": "number"}
        if annotation is str:
            return {"type": "string"}
        if annotation is bytes:
            return {"type": "string", "contentEncoding": "base16"}

    return {}


def _object_schema(cls: type, defs: dict[str, Any]) -> dict[str, Any]:
    hints = typing.get_type_hints(cls)
    properties: dict[str, Any] = {}
    required: list[str] = []
    for f in fields(cls):
        properties[f.name] = _schema_for(hints.get(f.name, Any), defs)
        if f.default is MISSING and f.default_factory is MISSING:  # type: ignore[misc]
            required.append(f.name)
    schema: dict[str, Any] = {
        "type": "object",
        "title": cls.__name__,
        "description": (cls.__doc__ or "").strip().split("\n")[0],
        "properties": properties,
    }
    if required:
        schema["required"] = required
    return schema


def json_schema(cls: type) -> dict[str, Any]:
    """Full JSON Schema document for one model, with nested types in $defs."""
    defs: dict[str, Any] = {}
    root = _object_schema(cls, defs)
    root["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    root["$id"] = f"https://securemailscope/schema/{cls.__name__}.json"
    if defs:
        root["$defs"] = defs
    return root


# --------------------------------------------------------------------------- #
# TypeScript
# --------------------------------------------------------------------------- #


def _ts_type(annotation: Any, seen: set[type]) -> str:
    annotation, optional = _unwrap(annotation)
    inner = _ts_type_concrete(annotation, seen)
    return f"{inner} | null" if optional else inner


def _ts_type_concrete(annotation: Any, seen: set[type]) -> str:
    if annotation is Any:
        return "unknown"
    origin = typing.get_origin(annotation)
    if origin in (list, tuple):
        args = typing.get_args(annotation) or (Any,)
        return f"{_ts_type(args[0], seen)}[]"
    if origin is dict:
        args = typing.get_args(annotation)
        value = args[1] if len(args) == 2 else Any
        return f"Record<string, {_ts_type(value, seen)}>"
    if isinstance(annotation, type):
        if is_dataclass(annotation) or issubclass(annotation, Enum):
            seen.add(annotation)
            return annotation.__name__
        if annotation is datetime:
            return "string"
        if annotation is bool:
            return "boolean"
        if annotation in (int, float):
            return "number"
        if annotation in (str, bytes):
            return "string"
    return "unknown"


def typescript() -> str:
    """Emit TypeScript interfaces for every model and enum in the contract."""
    out: list[str] = [
        "// GENERATED FILE - do not edit by hand.",
        "// Regenerate with:  python -m schema.jsonschema",
        "// Source of truth:  schema/models.py",
        "",
    ]

    enums: list[type] = []
    dataclasses_: list[type] = []
    for name in dir(models):
        obj = getattr(models, name)
        if not isinstance(obj, type) or obj.__module__ not in ("schema.models", "schema.enums", "schema.base"):
            continue
        if issubclass(obj, Enum):
            enums.append(obj)
        elif is_dataclass(obj):
            dataclasses_.append(obj)

    # Enums referenced through models live in schema.enums; pull them in too.
    from . import enums as enums_module
    for name in dir(enums_module):
        obj = getattr(enums_module, name)
        if isinstance(obj, type) and issubclass(obj, Enum) and obj is not Enum and obj not in enums:
            enums.append(obj)

    from .base import Evidence
    if Evidence not in dataclasses_:
        dataclasses_.append(Evidence)

    for enum_cls in sorted(enums, key=lambda c: c.__name__):
        values = " | ".join(f'"{m.value}"' for m in enum_cls)
        out.append(f"export type {enum_cls.__name__} = {values};")
    out.append("")

    seen: set[type] = set()
    for cls in sorted(dataclasses_, key=lambda c: c.__name__):
        hints = typing.get_type_hints(cls)
        doc = (cls.__doc__ or "").strip().split("\n")[0]
        if doc:
            out.append(f"/** {doc} */")
        out.append(f"export interface {cls.__name__} {{")
        for f in fields(cls):
            out.append(f"  {f.name}: {_ts_type(hints.get(f.name, Any), seen)};")
        out.append("}")
        out.append("")

    return "\n".join(out)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    out_dir = root / "schema" / "generated"
    out_dir.mkdir(parents=True, exist_ok=True)

    for name in TOP_LEVEL:
        cls = getattr(models, name)
        target = out_dir / f"{name}.schema.json"
        target.write_text(json.dumps(json_schema(cls), indent=2), encoding="utf-8")
        print(f"wrote {target.relative_to(root)}")

    ts_dir = root / "web" / "src" / "types"
    ts_dir.mkdir(parents=True, exist_ok=True)
    ts_target = ts_dir / "schema.ts"
    ts_target.write_text(typescript(), encoding="utf-8")
    print(f"wrote {ts_target.relative_to(root)}")


if __name__ == "__main__":
    main()
