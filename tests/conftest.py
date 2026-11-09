import os
import tempfile

import pytest

# Module/session-scoped fixtures run before the per-test fixture below, so set a safe default at import.
os.environ["NETTRACE_AUDIT_LOG"] = os.path.join(tempfile.mkdtemp(prefix="nettrace-audit-"), "audit.log")


@pytest.fixture(autouse=True)
def _audit_log_in_tmp(tmp_path, monkeypatch):
    """Nothing in the suite may write to the real ~/.local/state/nettrace/audit.log."""
    monkeypatch.setenv("NETTRACE_AUDIT_LOG", str(tmp_path / "audit" / "audit.log"))
