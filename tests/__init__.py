"""Test package. Ensures fixtures are importable under both unittest and pytest."""
import os
import sys

_FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
if _FIXTURES not in sys.path:
    sys.path.insert(0, _FIXTURES)
