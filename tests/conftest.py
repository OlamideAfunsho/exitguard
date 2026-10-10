import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from exitguard.sim.session import Session  # noqa: E402
from exitguard.sim.world import World  # noqa: E402


@pytest.fixture(scope="session")
def world():
    """A read-only world shared by tests that only look at it."""
    return World(shared_limit=True, controlled=True)


@pytest.fixture()
def session(tmp_path):
    s = Session(World(), tmp_path)
    yield s
    s.close()
