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
# ── Shodan credit policy ───────────────────────────────────────────────────
# A Shodan Membership grants 100 query credits + 100 scan credits per MONTH
# (they reset at the start of the month and do not demonstrably roll over),
# but almost the entire useful API surface is FREE: host lookups, host/count
# with facets, DNS, and the meta endpoints cost 0 credits. Only
# /shodan/host/search bills — 1 credit per 100 results — and only when the
# query carries a filter or you page past the first page.
#
# Because those credits are scarce and shared across every investigation, the
# credit-consuming path is OFF by default: `shodan_search` refuses and points
# at the free equivalents unless an operator explicitly opts in. Set
# BOUNCE_SHODAN_ALLOW_CREDITS=1 to permit it, and BOUNCE_SHODAN_CREDIT_BUDGET
# to cap how many credits a single process may spend (0 = unlimited once
# allowed). On-demand scanning (/shodan/scan) is never wired up: it spends
# scan credits AND actively touches the target, which breaks the platform's
# passive-only posture.
# Read live (not captured at import) so the policy is honoured after a reload
# and is trivially testable with monkeypatch.setenv.
def shodan_credits_allowed() -> bool:
    """True if this instance may spend Shodan query credits. Default False."""
    raw = os.getenv("BOUNCE_SHODAN_ALLOW_CREDITS")
    if raw is None or not raw.strip():
        return False
    return raw.strip().lower() in ("1", "true", "yes", "on")


def shodan_credit_budget() -> int:
    """Max query credits one process may spend (0 = unlimited once allowed)."""
    try:
        return max(0, int(os.getenv("BOUNCE_SHODAN_CREDIT_BUDGET", "0") or 0))
    except ValueError:
        return 0

CLAUDE_BIN = os.getenv("CLAUDE_BIN", "claude")
# OpenCTI base URL. The API key is read through key_pool ("opencti").
# The demo instance lives at https://demo.opencti.io and accepts the
# token format `flgrn_octi_tkn_…` as a bearer header.
OPENCTI_URL = os.getenv("OPENCTI_URL", "https://demo.opencti.io").rstrip("/")
