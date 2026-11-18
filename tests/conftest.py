import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.models import Extraction  # noqa: E402


def load(name: str) -> Extraction:
    return Extraction.model_validate(json.loads((ROOT / "samples" / f"{name}.json").read_text()))


def map_all(ex: Extraction, names=("GigabitEthernet0/1", "GigabitEthernet0/2")) -> Extraction:
    for r in ex.routers():
        for i, n in zip(sorted(r.interfaces, key=lambda x: x.id), names):
            i.name = n
    return ex


@pytest.fixture
def exam():
    return load("exam_plan")


@pytest.fixture
def alt():
    return load("alt_plan")


INV = {"R1": {"mgmt_ip": "192.168.122.11", "port": 22}, "R2": {"mgmt_ip": "192.168.122.12", "port": 22},
       "RTR-A": {"mgmt_ip": "192.168.122.21"}, "RTR-B": {"mgmt_ip": "192.168.122.22"}}
