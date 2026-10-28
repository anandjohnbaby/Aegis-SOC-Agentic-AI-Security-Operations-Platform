from shared.schemas import Alert
from lg_flow.run import run_investigation


def test_full_pipeline_mock():
    inv = run_investigation(Alert(title="integration test",
                                  target="http://localhost:5000"))
    assert inv.status == "completed"
    assert inv.findings and inv.report is not None
    # high/critical findings should have produced tickets
    assert len(inv.tickets) >= 1
    assert len(inv.trace) >= 6         # one trace line per agent node
