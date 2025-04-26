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
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", None)
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", None)

MISP_URL = os.getenv("MISP_URL", None)
MISP_API_KEY = os.getenv("MISP_API_KEY", None)
MISP_VERIFYCERT = os.getenv("MISP_VERIFYCERT", "True").lower() == "False"  # Option for self-signed certs

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

# --- FireHOL Feeds ---
FIREHOL_FEEDS = {
    # Main FireHOL levels
    "level1": os.getenv("FIREHOL_LEVEL1_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"),
    "level2": os.getenv("FIREHOL_LEVEL2_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset"),
    "level3": os.getenv("FIREHOL_LEVEL3_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset"),
    "level4": os.getenv("FIREHOL_LEVEL4_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level4.netset"),

    # Main components that make up Level 1 & 2 protection
    "dshield": os.getenv("DSHIELD_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset"),
    "spamhaus_drop": os.getenv("SPAMHAUS_DROP_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset"),
    "spamhaus_edrop": os.getenv("SPAMHAUS_EDROP_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_edrop.netset"),
    "blocklist_de": os.getenv("BLOCKLIST_DE_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_de.ipset"),
    "bruteforceblocker": os.getenv("BRUTEFORCEBLOCKER_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/bruteforceblocker.ipset"),
    "et_block": os.getenv("ET_BLOCK_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/et_block.netset"),
    "feodo": os.getenv("FEODO_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/feodo.ipset"),
    "malc0de": os.getenv("MALC0DE_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/malc0de.ipset"),

    # Extras (mostly crime related)
    "webclient": os.getenv("FIREHOL_WEBCLIENT_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_webclient.netset"),
    "alienvault_reputation": os.getenv("ALIENVAULT_REPUTATION_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/alienvault_reputation.ipset"),
    "cybercrime": os.getenv("CYBERCRIME_TRACKER_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/cybercrime.ipset"),

    "stopforumspam_365d": os.getenv("STOPFORUMSPAM_365D_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/stopforumspam_365d.ipset"),
    "dronebl_irc_drones": os.getenv("DRONEBL_IRC_DRONES_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dronebl_irc_drones.ipset"),
    "firehol_abusers_30d": os.getenv("FIREHOL_ABUSERS_30D_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_abusers_30d.netset"),
    "stopforumspam": os.getenv("STOPFORUMSPAM_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/stopforumspam.ipset"),
    "blocklist_net_ua": os.getenv("BLOCKLIST_NET_UA_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_net_ua.ipset"),
    "cleantalk_updated_30d": os.getenv("CLEANTALK_UPDATED_30D_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cleantalk_updated_30d.ipset"),
    "botscout_30d": os.getenv("BOTSCOUT_30D_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/botscout_30d.ipset"),
    "sblam": os.getenv("SBLAM_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/sblam.ipset"),
    "gpf_comics": os.getenv("GPF_COMICS_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/gpf_comics.ipset"),
    "iblocklist_forumspam": os.getenv("IBLOCKLIST_FORUMSPAM_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/iblocklist_forumspam.ipset"),
    "graphiclineweb": os.getenv("GRAPHICLINEWEB_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/graphiclineweb.ipset"),
    "cleantalk_top20": os.getenv("CLEANTALK_TOP20_URL", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cleantalk_top20.ipset")
}
# Extra feeds found in the wild - mostly from independent security professionals
OTHER_FEEDS = {
    "ipsum": os.getenv("IPSUM_URL", "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"),
}

DEFAULT_USER_AGENT = "ThreatIntelTool/0.3"
USER_AGENT = os.getenv("USER_AGENT", DEFAULT_USER_AGENT)
