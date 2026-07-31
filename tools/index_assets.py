import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from trb_depot_agents.assets import AssetCatalog


if __name__ == "__main__":
    result = AssetCatalog().write_registry()
    print(result["bundle_id"])
