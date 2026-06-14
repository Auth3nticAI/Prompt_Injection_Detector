"""Point the app at a throwaway SQLite file before it is imported."""
import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="pid-test-")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
