"""Strata Cloud Manager configuration API simulator (GET only)."""

from __future__ import annotations

from typing import Any

from nettrace.demo.lab import SCM
from nettrace.errors import DeviceError


def get(endpoint: str, params: dict[str, Any]) -> dict[str, Any]:
    folder = params.get("folder")
    offset, limit = int(params.get("offset", 0)), int(params.get("limit", 500))
    if endpoint == "/config/security/v1/security-rules":
        rules = SCM["rules"].get(folder, []) if params.get("position", "pre") == "pre" else []
        data = [dict(r, folder=folder, id=f"rule-{i}") for i, r in enumerate(rules)]
    elif endpoint.startswith("/config/objects/v1/"):
        kind = endpoint.rsplit("/", 1)[1]
        if kind not in SCM["objects"]:
            raise DeviceError(f"SCM GET {endpoint}: HTTP 404")
        data = [dict(o, folder="Shared") for o in SCM["objects"][kind]]
    else:
        raise DeviceError(f"SCM GET {endpoint}: HTTP 404")
    return {"data": data[offset:offset + limit], "offset": offset, "limit": limit, "total": len(data)}
