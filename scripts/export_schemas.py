"""Write the data contracts as JSON Schema files into ./schemas."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.models import Extraction, JobMessage, ResultMessage  # noqa: E402

out = ROOT / "schemas"
out.mkdir(exist_ok=True)
for name, model in {"extraction": Extraction, "job": JobMessage, "result": ResultMessage}.items():
    (out / f"{name}.schema.json").write_text(json.dumps(model.model_json_schema(), indent=2) + "\n")
    print("wrote", out / f"{name}.schema.json")
