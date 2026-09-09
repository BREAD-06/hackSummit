"""Make the repository root importable so tests can ``import vigil`` / ``server`` / ``agent``.

pytest imports the rootdir ``conftest.py`` first; adding the repo root to
``sys.path`` here means every test module can import the project packages
regardless of the current working directory.
"""

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
