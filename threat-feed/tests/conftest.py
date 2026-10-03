import os
import sys
from pathlib import Path

os.environ.setdefault("THREATFEED_DB_PATH", ":memory:")
os.environ.setdefault("THREATFEED_INGEST", "0")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
