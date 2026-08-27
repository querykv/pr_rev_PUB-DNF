"""Per-run telemetry (cross-cutting §11). M0 records phase timings, tool
availability and finding counts; token/$ accounting wires in at M1 with the model
provider."""
from __future__ import annotations

import json
import time
from contextlib import contextmanager
from pathlib import Path


class Telemetry:
    def __init__(self) -> None:
        self.data: dict = {
            "phases": {},
            "meta": {},
            "tokens": {"input": 0, "output": 0},  # 0 in M0 (no AI)
        }

    @contextmanager
    def phase(self, name: str):
        t0 = time.perf_counter()
        try:
            yield
        finally:
            self.data["phases"][name] = round(time.perf_counter() - t0, 4)

    def set(self, key: str, value) -> None:
        self.data["meta"][key] = value

    def to_dict(self) -> dict:
        return self.data

    def write(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.data, indent=2))
