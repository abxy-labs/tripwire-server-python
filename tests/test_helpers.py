from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent


def load_fixture(relative_path: str) -> Any:
    return json.loads((ROOT / "spec" / "fixtures" / relative_path).read_text())
