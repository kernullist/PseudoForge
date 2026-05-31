from __future__ import annotations

import json
from typing import Any


class JsonRenameProvider:
    def __init__(self, payload: Any) -> None:
        self._payload = payload

    def suggest_renames(self, capture: Any) -> str:
        if isinstance(self._payload, str):
            return self._payload
        return json.dumps(self._payload)
