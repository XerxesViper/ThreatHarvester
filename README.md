# Threat Harvester

[![License](https://img.shields.io/badge/license-The_Unlicense-red.svg)](https://unlicense.org/)
```
___________.__                               __     ___ ___                                           __                   
\__    ___/|  |__  _______   ____  _____   _/  |_  /   |   \ _____   _______ ___  __  ____    _______/  |_   ____  _______ 
  |    |   |  |  \ \_  __ \_/ __ \ \__  \  \   __\/    ~    \\__  \  \_  __ \\  \/ /_/ __ \  /  ___/\   __\_/ __ \ \_  __ \
  |    |   |   Y  \ |  | \/\  ___/  / __ \_ |  |  \    Y    / / __ \_ |  | \/ \   / \  ___/  \___ \  |  |  \  ___/  |  | \/
  |____|   |___|  / |__|    \___  >(____  / |__|   \___|_  / (____  / |__|     \_/   \___  >/____  > |__|   \___  > |__|   
                \/              \/      \/               \/       \/                     \/      \/             \/
                                 ThreatHarvester V1.0 - XerxesViper

```
A command-line tool to aggregate Indicators of Compromise (IOCs) from various OSINT feeds, store them locally, and enrich queried indicators using external threat intelligence APIs.

![Threat Harvester Demo](https://codeberg.org/XerxesViper/Threat_Intel_Feed_Correlator/raw/branch/main/Media/ThreatHarvester_example_CLI.gif)


## Features

*   **Feed Aggregation:** Automatically downloads and parses IOCs from multiple sources:
    *   Abuse.ch Feodo Tracker (IPs)
    *   Abuse.ch Malware Bazaar (Hashes)
    *   Abuse.ch URLhaus (URLs)
    *   **Extensive FireHOL IP Lists:** Includes Levels 1-4 and numerous component lists (dshield, spamhaus\_drop/edrop, blocklist\_de, bruteforceblocker, et\_block, feodo, malc0de, webclient, alienvault\_reputation, cybercrime, stopforumspam, dronebl, etc.) providing categorized IP/CIDR blocklists (*26 total lists*).
    *   AlienVault OTX Pulses (IPs, Domains, Hashes, URLs, etc. from subscribed pulses)
    *   IPsum (IPs with report counts)
*   **Local IOC Database:** Stores aggregated IOCs (value, type, source, tags, timestamps) in a local SQLite database for quick lookups. Handles basic deduplication via `INSERT OR IGNORE`.
*   **CIDR Expansion:** Expands smaller CIDR blocks (<= /24, i.e., 256 addresses or fewer) from feeds into individual IPs for storage. Larger blocks are stored as `cidr` type.
*   **Batch Database Inserts:** Uses `executemany` for efficient insertion of IOCs into the SQLite database.
*   **IOC Enrichment:** Queries external APIs for context on a given IOC (IP, Domain, Hash, URL):
    *   VirusTotal API v3 (Detection ratios, Reputation, YARA hits, etc.)
    *   AbuseIPDB API v2 (Abuse score, Reports, Geolocation, URL reports, etc.)
    *   AlienVault OTX API v1 (Related Pulses, etc.)
    *   URLScan.io API v1 (Website scan details, Verdicts, Related Hashes, etc.)
    *   Shodan API (Open ports, Services, ASN, Geolocation, etc.)
    *   GreyNoise Community API (Noise detection, Classification, Actor, etc.)
    *   IPinfo.io API (Geolocation, ASN, Company, etc.)
    *   MalShare API (Hash existence check, Associated hashes, Filenames)
*   **Command-Line Interface:** Easy-to-use CLI for querying IOCs and selectively disabling enrichment sources.
*   **Configurable:** API keys and feed URLs managed via `.env` file and `src/config.py`.

## Screenshots / Demo

<!-- Placeholder: Add screenshots here -->
**IP Query Demo:**

![IP Query Demo](https://codeberg.org/XerxesViper/Threat_Intel_Feed_Correlator/raw/branch/main/Media/IPEnrichmentExample.gif)

**Hash Query Output:**

![IP Query Demo](https://codeberg.org/XerxesViper/Threat_Intel_Feed_Correlator/raw/branch/main/Media/HashQueryDemo.gif)

## Technology Stack

*   **Language:** Python 3.x
*   **Core Libraries:**
    *   `requests`: For HTTP requests (feeds/APIs)
    *   `sqlite3`: For the local IOC database
    *   `argparse`: For the command-line interface
    *   `python-dotenv`: For managing API keys via `.env` files
    *   `ipaddress`: For CIDR block handling
    *   `tqdm`: For progress bars during feed processing
    *   `shodan`: Official Shodan library for enrichment
    *   `OTXv2`: Official AlienVault OTX SDK v2 (used for feed ingestion)
    *    `re` : For Regular Expression (RegEx) compilation 
*   **Database:** SQLite

## Installation & Setup

1.  **Clone the repository:**
    ```bash
    # Make sure you have git installed
    git clone https://codeberg.org/XerxesViper/Threat_Intel_Feed_Correlator.git
    cd Threat_Intel_Feed_Correlator
    ```

2.  **Create and activate a virtual environment:** (Recommended)
    ```bash
    # On Windows
    python -m venv venv
    .\venv\Scripts\activate

    # On macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure API Keys:**
    *   Copy the example environment file:
        ```bash
        # Use 'copy' on Windows CMD, 'cp' on Linux/macOS/Git Bash
        cp .env.example .env 
        ```
    *   Edit the `.env` file with a text editor and add your API keys/tokens for the enrichment services and feeds you want to use:
        ```dotenv
        # .env file - Add your keys below
        VT_API_KEY=
        ABUSEIPDB_API_KEY=
        OTX_API_KEY=
        URLSCAN_API_KEY=
        SHODAN_API_KEY=
        GREYNOISE_API_KEY=
        IPINFO_TOKEN=
        MALSHARE_API_KEY=
        DATABASE_PATH=
        # MISP_URL= # Uncomment and set if using MISP enrichment later
        # MISP_API_KEY= # Uncomment and set if using MISP enrichment later
        # MISP_VERIFYCERT=False # Set to True if MISP has valid SSL
        ```
    *   **Important:** Ensure `.env` is listed in your `.gitignore` file!

5.  **Initialize the Database:**
    *   Run the database initialization script (creates `data/threat_intel.db`):
    ```bash
    python scripts/initialize_db.py
    ```

6.  **Populate the Database with Feeds:**
    *   Run the feed handler script. This downloads and processes all configured feeds. **This will take a significant amount of time initially due to the large number of FireHOL feeds.**
    ```bash
    # Run from the project root directory
    python -m src.feed_handler 
    ```
    *   Schedule this script to run periodically (e.g., daily) to keep the database updated.
    *   Else If you would like to download the database that has already been created - It can be downloaded from - 

## Usage

Query an Indicator of Compromise (IOC) using the command line:

```bash
python -m threat_intel_cli -i <IOC_VALUE> [options]
```

For help regarding the functionality:

```shell
python -m threat_intel_cli -h
```

**Arguments:**

*   `-i IOC`, `--ioc IOC`: **(Required)** The indicator value to query (e.g., IP, domain, URL, MD5/SHA1/SHA256 hash).

**Options (Flags to Disable Enrichment):**

*   `--no_VT`: Disable VirusTotal enrichment.
*   `--no_AIPDB`: Disable AbuseIPDB enrichment.
*   `--no_OTX`: Disable AlienVault OTX enrichment.
*   `--no_URLSCAN`: Disable URLScan.io enrichment.
*   `--no_SHODAN`: Disable Shodan enrichment.
*   `--no_GREYNOISE`: Disable GreyNoise enrichment.
*   `--no_IPINFO`: Disable IPinfo.io enrichment.
*   `--no_MALSHARE`: Disable MalShare enrichment.
*   `--no_MISP`: Disable MISP enrichment (if implemented later).
*   `--Local` : Disable all enrichment (Offline Mode)

**Examples:**

```bash
# Query an IP address (enrich with all available sources)
python -m threat_intel_cli -i 183.162.197.57

# Query a domain, skipping Shodan and GreyNoise (which only apply to IPs anyway)
python -m threat_intel_cli -i www.xw.ru.com.camaleonrd.com.tr --no_SHODAN --no_GREYNOISE

# Query a file hash, skipping VirusTotal enrichment
python -m threat_intel_cli -i d93275559eb83215203d6513dfe9b371 --no_VT

# Query a URL, disabling OTX and MalShare (which don't apply)
python -m threat_intel_cli -i "http://some-malicious-url.com/payload.exe" --no_OTX --no_MALSHARE
```

## Feed Sources

The tool currently aggregates data from the following sources:

| Source                 | IOC Types               | Notes                                                                                       |
| :--------------------- | :---------------------- | :------------------------------------------------------------------------------------------ |
| Abuse.ch Feodo         | `ipv4`                  | Botnet C2 IPs                                                                               |
| Abuse.ch MalwareBazaar | `md5`, `sha1`, `sha256` | Malware sample hashes & context                                                             |
| Abuse.ch URLhaus       | `url`                   | Malicious URLs                                                                              |
| FireHOL (Multiple)     | `ipv4`, `cidr`          | ~25+ lists including Levels 1-4, dshield, spamhaus_drop/edrop, blocklist_de, et_block, etc. |
| AlienVault OTX         | Various                 | Pulses containing diverse IOC types                                                         |
| IPsum                  | `ipv4`                  | IPs with report counts (added as tags)                                                      |

## Enrichment Sources

Queried IOCs are enriched using these external APIs:

| Service       | Supported IOC Types              | Notes                        |
| :------------ | :------------------------------- | :--------------------------- |
| VirusTotal    | `ipv4`, `domain`, `url`, `hash`  | Detections, Reputation, YARA |
| AbuseIPDB     | `ipv4`, `url`                    | Abuse Score, Reports         |
| OTX           | `ipv4`, `domain`, `url`, `hash`  | Related Pulses               |
| URLScan.io    | `ipv4`, `domain`, `url`, `hash`  | Website Scan Details         |
| Shodan        | `ipv4`                           | Ports, Services, Geo, ASN    |
| GreyNoise     | `ipv4`                           | Noise/RIOT Classification    |
| IPinfo.io     | `ipv4`                           | GeoIP, ASN Details           |
| MalShare      | `hash` (`md5`, `sha1`, `sha256`) | Hash Existence, Metadata     |
| <!-- MISP --> | <!-- `ipv4`, `domain`, etc. -->  | <!-- Event Context -->       |

## Future Enhancements / Roadmap

*   [ ] MISP Debugging (*Ongoing*)
*   [ ] Implement robust database update logic for `sources` tag.
*   [ ] Implement IOC aging/purging.
*   [ ] Add `feeds` table to track updates.
*   [ ] Improve error handling (retries for rate limits).
*   [ ] Consistent logging implementation.
*   [ ] Add more feed sources (e.g., specific GitHub repos).
*   [ ] Add more enrichment sources (e.g., URLScan submit).
*   [ ] Revisit MISP integration (feed and/or enrichment).
*   [ ] Add more CLI commands (`update-feeds`, `purge-db`).
*   [ ] Add output formats (`--json`).
*   [ ] Automation examples (`schedule`, cron).
*   [ ] Unit/integration tests.
*   [ ] Potential Web UI (Streamlit).

## Contributing and Requests

If you have request for any feature or anything else - Please drop me an email or message or just open an issue. I will be happy to do whatever I can.

All Contributions are welcome! Please feel free to submit a Pull Request or open an Issue.