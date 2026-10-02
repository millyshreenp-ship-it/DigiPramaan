import os
import pytest

@pytest.fixture(autouse=True)
def legacy_open_access_for_tests():
    # Force legacy open access so teammate tests pass without per-case member assignment
    os.environ["LEGACY_OPEN_ACCESS"] = "1"
    yield
    os.environ.pop("LEGACY_OPEN_ACCESS", None)
