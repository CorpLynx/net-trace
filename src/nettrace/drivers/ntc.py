from __future__ import annotations

from typing import Any

from ntc_templates.parse import parse_output

from nettrace.errors import DeviceError


def ntc_parse(command: str, data: str, platform: str = "cisco_ios") -> list[dict[str, Any]]:
    """ntc-templates parse with upper-case keys (matching the template Value names).

    Empty output is an empty list. Anything the parser cannot handle raises DeviceError, so a
    template mismatch is never read as "no rows" (and so as "no ACL").
    """
    if not data.strip():
        return []
    try:
        rows = parse_output(platform=platform, command=command, data=data)
    except Exception as exc:  # textfsm / clitable raise on output they don't recognise
        raise DeviceError(f"could not parse '{command}' output ({type(exc).__name__})") from None
    return [{k.upper(): v for k, v in row.items()} for row in rows]
