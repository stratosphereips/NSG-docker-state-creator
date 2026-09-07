"""Fixture loaders for the FM detector battery.

Every detector test builds its Observation through ``load_fixture(name)``,
which loads ``tests/fm/fixtures/<name>`` as if it were an /observation
directory (see tests/fm/fixtures/README.md for the fixture format).
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow: python3.12 -m pytest tests/fm
    sys.path.insert(0, str(REPO_ROOT))

from analysis.observation import Observation, load_observation  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def load_fixture(name: str) -> Observation:
    """Load fixtures/<name> as an /observation directory."""
    return load_observation(FIXTURES / name)


def fixture_path(name: str) -> Path:
    """Absolute path of a fixture case directory."""
    return FIXTURES / name
