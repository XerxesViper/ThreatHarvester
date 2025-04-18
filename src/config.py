import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
dotenv_path = os.path.join(os.path.dirname(__file__), '..', '.env')

load_dotenv(dotenv_path=dotenv_path)

# --- API Keys ---
# Load from environment variable or default to None if not set
VT_API_KEY = os.getenv("VT_API_KEY", None)
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", None)
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", None)
OTX_API_KEY = os.getenv("OTX_API_KEY", None)

# --- Database Path ---
DEFAULT_DB_PATH = "data/threat_intel.db"
DATABASE_PATH = os.getenv("DATABASE_PATH", DEFAULT_DB_PATH)

# Load from environment or use hardcoded defaults
DEFAULT_FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
FEODO_TRACKER_URL = os.getenv("FEODO_TRACKER_URL", DEFAULT_FEODO_URL)

DEFAULT_MALWARE_BAZAAR_URL = "https://bazaar.abuse.ch/export/csv/recent/"
MALWARE_BAZAAR_URL = os.getenv("MALWARE_BAZAAR_URL", DEFAULT_MALWARE_BAZAAR_URL)

DEFAULT_URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
URLHAUS_URL = os.getenv("URLHAUS_URL", DEFAULT_URLHAUS_URL)

DEFAULT_USER_AGENT = "ThreatIntelTool/0.2"
USER_AGENT = os.getenv("USER_AGENT", DEFAULT_USER_AGENT)
