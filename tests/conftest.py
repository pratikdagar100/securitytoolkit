import os
import tempfile

import pytest

from security_toolkit.core.config import Config, DEFAULTS
from security_toolkit.core.case_manager import Workspace, CaseManager


@pytest.fixture()
def workspace(tmp_path):
    data = dict(DEFAULTS)
    data["workspace"] = str(tmp_path / "ws")
    ws = Workspace(Config(data))
    yield ws
    ws.close()


@pytest.fixture()
def case_manager(workspace):
    return CaseManager(workspace)
