"""pytest configuration (the suite also runs under `python -m unittest`)."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fixtures"))
# Isolate data dir for the whole test session.
os.environ.setdefault("VELORA_DATA_DIR", tempfile.mkdtemp(prefix="vf-test-"))
os.environ.setdefault("VELORA_CONFIG_DIR", tempfile.mkdtemp(prefix="vf-cfg-"))
