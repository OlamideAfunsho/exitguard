"""Every negative control must raise its blocker and publish nothing clean."""

import pytest

from exitguard.sim.controls import CONTROLS


@pytest.mark.parametrize("control", CONTROLS, ids=[c.key for c in CONTROLS])
def test_control_is_refused(control, tmp_path):
    outcome = control.run(tmp_path)
    assert control.expect in outcome.codes, f"expected {control.expect}, got {sorted(outcome.codes)}"
    assert outcome.published == []
