from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path

from .settings import load_settings


class AssetKind(StrEnum):
    CAD = "cad"
    TIMETABLE = "timetable"
    ROUTE_LIBRARY = "route-library"


EXTENSIONS: dict[AssetKind, frozenset[str]] = {
    AssetKind.CAD: frozenset({".dxf", ".dwg", ".json"}),
    AssetKind.TIMETABLE: frozenset({".csv", ".xlsx", ".json"}),
    AssetKind.ROUTE_LIBRARY: frozenset({".csv", ".json", ".yaml", ".yml"}),
}


@dataclass(frozen=True)
class AssetReference:
    asset_id: str
    kind: str
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    relative_path: str


class AssetCatalog:
    def __init__(self, root: str | Path | None = None) -> None:
        configured = root or load_settings().assets.root
        self.root = Path(configured).resolve()

    @staticmethod
    def _directory(kind: AssetKind) -> str:
        return "route_library" if kind is AssetKind.ROUTE_LIBRARY else kind.value

    def scan(self) -> list[dict]:
        references: list[dict] = []
        for kind in AssetKind:
            directory = self.root / self._directory(kind)
            if not directory.is_dir():
                continue
            for path in sorted(item for item in directory.iterdir() if item.is_file()):
                if path.suffix.lower() not in EXTENSIONS[kind]:
                    continue
                content = path.read_bytes()
                references.append(
                    asdict(
                        AssetReference(
                            asset_id=f"{kind.value}-{hashlib.sha256(content).hexdigest()[:12]}",
                            kind=kind.value,
                            filename=path.name,
                            content_type="application/octet-stream",
                            size_bytes=len(content),
                            sha256=hashlib.sha256(content).hexdigest(),
                            relative_path=str(path.relative_to(self.root)).replace("\\", "/"),
                        )
                    )
                )
        return references

    def write_registry(self, path: str | Path = "data/registry/assets.json") -> dict:
        records = self.scan()
        payload = {
            "bundle_id": hashlib.sha256(
                json.dumps(records, sort_keys=True).encode("utf-8")
            ).hexdigest()[:16],
            "assets": records,
        }
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return payload
