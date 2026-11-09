import pytest

from nettrace.demo import PRESETS, install
from nettrace.engine import Tracer
from nettrace.models import Flow


@pytest.fixture(scope="module")
def inv():
    return install()


def test_preset_count():
    assert len(PRESETS) == 12


@pytest.mark.parametrize("preset", PRESETS, ids=[p["id"] for p in PRESETS])
def test_preset_outcome(inv, preset):
    f = dict(preset["flow"])
    start_at = f.pop("start_at", None)
    flow = Flow(src=f["src"], dst=f["dst"], protocol=f["protocol"], dst_port=f["port"],
                application=f.get("application"), user=f.get("user"))
    result = Tracer(inv).trace(flow, start_at=start_at)
    assert result.outcome.value == preset["expect"], result.reason
