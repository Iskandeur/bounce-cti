import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "bounce.db"

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY", "")
ONYPHE_KEY = os.getenv("ONYPHE_API_KEY", "")
SHODAN_KEY = os.getenv("SHODAN_API_KEY", "")
OTX_KEY = os.getenv("OTX_API_KEY", "")
# abuse.ch (URLhaus + MalwareBazaar) auth key — free, register at https://auth.abuse.ch/
ABUSECH_KEY = os.getenv("ABUSECH_AUTH_KEY", "")
CLAUDE_BIN = os.getenv("CLAUDE_BIN", "claude")
# OpenCTI base URL. The API key is read through key_pool ("opencti").
# The demo instance lives at https://demo.opencti.io and accepts the
# token format `flgrn_octi_tkn_…` as a bearer header.
OPENCTI_URL = os.getenv("OPENCTI_URL", "https://demo.opencti.io").rstrip("/")
