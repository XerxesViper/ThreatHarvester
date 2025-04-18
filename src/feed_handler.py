import re
import io
import csv
import requests
import datetime
from tqdm import tqdm

try:
    from OTXv2 import OTXv2

    OTX_SDK_AVAILABLE = True
except ImportError:
    print("[Warning] OTXv2 SDK not installed. OTX feed processing will be skipped.")
    OTX_SDK_AVAILABLE = False

# Local Imports
from . import config
from .db_manager import add_ioc


def fetch_feed_content(url, timeout=30):
    """ Fetches the contents of a feed from a given URL. """

    user_agent = getattr(config, "USER_AGENT", 'ThreatIntelTool/0.1-TEST')

    try:
        response = requests.get(url, timeout=timeout, headers={'User-Agent': user_agent})
        response.raise_for_status()
        print(f"Feed contents fetched successfully from {url}")
        return response.text

    except requests.exceptions.RequestException as e:
        print(f"Error fetching feed contents from {url}: {e}")
        return None


"""
===========================================================
Feodo Tracker feed functions
===========================================================
"""

# Basic IPv4 regex matching pattern
IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def process_feodo_tracker_feed(feed_content, db_path, source_name="FeodoTrackerIPBlocklist", feed_url=None):
    """Parses Feodo Tracker IP list and adds IOCs to the DB."""
    if not feed_content:
        print(f"No content received for {source_name}, skipping processing.")
        return 0

    added_count = 0
    processed_count = 0
    lines = feed_content.strip().splitlines()

    for line in lines:
        processed_count += 1
        ip = line.strip()

        # print(ip)

        # Skipping the lines that are empty or, are comments
        if not ip or ip.startswith("#"):
            continue

        # Validating IPv4 addresses
        if IP_PATTERN.match(ip):
            add_ioc(
                db_path=db_path,
                ioc_value=ip,
                ioc_type='ipv4',
                sources=source_name,
                feed_url=feed_url
            )

            added_count += 1
            print(f"New IOC added to database: {ip} (IPv4)")

        else:
            print(f"Skipping invalid IP address: {ip}")

    print(f"Processed {processed_count} lines for {source_name}. Potential additions handled by add_ioc.")
    return processed_count


def update_feodo_tracker(db_path=config.DATABASE_PATH, url=config.FEODO_TRACKER_URL):
    """Fetches and processes the Feodo Tracker IP blocklist."""
    print(f"Starting update for Feodo Tracker from {url}...")

    feed_content = fetch_feed_content(url)

    if feed_content:
        print(f"Successfully fetched feed content ({len(feed_content)} bytes). Processing...")
        processed_count = process_feodo_tracker_feed(
            feed_content=feed_content,
            db_path=db_path,
            source_name="FeodoTrackerIPBlocklist",
            feed_url=url
        )
        print(f"Finished processing Feodo Tracker feed. Processed {processed_count} lines.")

    else:
        print("Failed to fetch Feodo Tracker feed - skipping processing.")


"""
===========================================================
Malware Bazaar feed functions
===========================================================
"""

MALWARE_BAZAAR_HEADERS = [
    "first_seen_utc", "sha256_hash", "md5_hash", "sha1_hash", "reporter",
    "file_name", "file_type_guess", "mime_type", "signature", "clamav",
    "vtpercent", "imphash", "ssdeep", "tlsh"
]


# Helper function to clean potentially quoted values
def clean_value(value):
    """Removes leading/trailing whitespace and surrounding quotes."""
    if value is None:
        return None
    # Strip whitespace first, then quotes
    return value.strip().strip('"')


def process_malware_bazaar_feed(feed_content, db_path=config.DATABASE_PATH, source_name="MalwareBazaarRecent", feed_url=config.MALWARE_BAZAAR_URL):
    """Parses Malware Bazaar CSV feed and adds IOCs (MD5, SHA256) to the DB."""
    if not feed_content:
        print(f"No content received for {source_name}, skipping processing.")
        return 0

    # # --- DEBUG: Print raw content representation ---
    # print("--- Raw Feed Content Snippet (repr) ---")
    # print(repr(feed_content[:500]))
    # print("--- End Raw Feed Content Snippet ---")
    # # --- END DEBUG ---

    processed_hashes = 0

    csv_file = io.StringIO(feed_content)

    # Count total data rows for progress bar
    csv_file.seek(0)  # Ensure we are at the start
    # Count lines that are NOT comments
    total_rows = sum(1 for line in csv_file if not line.startswith('#'))
    csv_file.seek(0)

    # Filter comments before passing to DictReader
    data_lines_iterable = (line for line in csv_file if not line.startswith('#'))

    # Using DictReader with proper setting based on raw input
    reader = csv.DictReader(
        data_lines_iterable,
        fieldnames=MALWARE_BAZAAR_HEADERS,
        delimiter=',',
        skipinitialspace=True  # Handles the space after the comma
    )
    print(f"Found {total_rows} data rows to process for {source_name}.")

    try:
        pbar = tqdm(reader, total=total_rows, desc=f"Processing {source_name}", unit="entries")
        for row in pbar:
            # Now 'row' should be a dictionary with correct keys and values

            # Getting and clean the values
            # Apply clean_value to remove potential quotes left by reader/extra space
            first_seen = clean_value(row.get('first_seen_utc', None))
            first_seen = row.get('first_seen_utc', None)
            sha256 = clean_value(row.get('sha256_hash', None))
            sha1 = clean_value(row.get('sha1_hash', None))
            md5 = clean_value(row.get('md5_hash', None))

            signature = clean_value(row.get('signature', None))
            file_type = clean_value(row.get('file_type_guess', None))
            mime_type = clean_value(row.get('mime_type', None))
            file_name = clean_value(row.get('file_name', None))

            db_tags_list = []

            # Add Signature
            if signature and signature.lower() not in ["", "n/a"]:
                db_tags_list.append(f"signature: {signature}")

            # Add file type
            if file_type and file_type.lower() not in ["", "n/a"]:
                db_tags_list.append(f"file_type: {file_type}")

            # Add mime type
            if mime_type and mime_type.lower() not in ["", "n/a"]:
                db_tags_list.append(f"mime: {mime_type}")

            # Optional: Add filename if present and meaningful
            if file_name and file_name.lower() not in ["", "n/a"]:
                db_tags_list.append(f"filename: {file_name}")

            # Combining all tags into one for db addition
            final_tags_for_db = ",".join(db_tags_list) if db_tags_list else None

            # print(f"Cleaned SHA256: {sha256}, MD5: {md5}, Tags: {final_tags_for_db}")

            # Adding SHA256 hash if present
            if sha256:
                # print(f"Processing SHA256: {sha256}")
                add_ioc(
                    db_path=db_path,
                    ioc_value=sha256,
                    ioc_type='sha256',
                    sources=source_name,
                    feed_url=feed_url,
                    first_seen_feed=first_seen,
                    tags=final_tags_for_db
                )
                processed_hashes += 1

            # Adding SHA1 hash if present
            if sha1:
                add_ioc(
                    db_path=db_path,
                    ioc_value=sha1,
                    ioc_type='sha1',
                    sources=source_name,
                    feed_url=feed_url,
                    first_seen_feed=first_seen,
                    tags=final_tags_for_db
                )
                processed_hashes += 1

            # Adding md5 checksum if present
            if md5:
                # print(f"Processing MD5: {md5}")
                add_ioc(
                    db_path=db_path,
                    ioc_value=md5,
                    ioc_type='md5',
                    sources=source_name,
                    feed_url=feed_url,
                    first_seen_feed=first_seen,
                    tags=final_tags_for_db
                )
                processed_hashes += 1

    except csv.Error as e:
        print(f"CSV parsing error in {source_name}: {e}")

        return 0

    print(f"Processed {processed_hashes} hashes for {source_name}.")
    return processed_hashes


def update_malware_bazaar(db_path=config.DATABASE_PATH, url=config.MALWARE_BAZAAR_URL):
    """Fetches and processes the Malware Bazaar recent CSV feed."""

    print(f"Starting update for Malware Bazaar from {url}...")

    feed_content = fetch_feed_content(url)
    if feed_content:
        print(f"Successfully fetched Malware Bazaar feed ({len(feed_content)} bytes). Processing...")
        processed_count = process_malware_bazaar_feed(
            feed_content=feed_content,
            db_path=db_path,
            source_name="MalwareBazaarRecent",
            feed_url=url
        )
        print(f"Finished processing Malware Bazaar feed. Processed {processed_count} hashes.")

    else:
        print("Failed to fetch Malware Bazaar feed - skipping processing.")


"""
===========================================================
URLHaus feed functions
===========================================================
"""

URLHAUS_HEADERS = [
    "id", "dateadded", "url", "url_status", "last_online",
    "threat", "tags", "urlhaus_link", "reporter"
]
URLHAUS_SOURCE_NAME = "URLhausRecent"


def process_urlhaus_feed(feed_content, db_path, source_name=URLHAUS_SOURCE_NAME, feed_url=None):
    """Parses URLhaus recent CSV feed and adds URL IOCs to the DB."""
    if not feed_content:
        print(f"No content received for {source_name}, skipping processing.")
        return 0

    processed_urls = 0
    csv_file = io.StringIO(feed_content)

    data_line_iterable = (line for line in csv_file if not line.startswith('#'))

    reader = csv.DictReader(data_line_iterable, fieldnames=URLHAUS_HEADERS, delimiter=',')

    print(f"Processing {source_name} feed...")

    try:
        for row in reader:
            url_value = clean_value(row.get('url', None))
            date_added = clean_value(row.get('dateadded', None))
            threat_type = clean_value(row.get('threat', None))
            feed_tags = clean_value(row.get('tags', None))
            urlhaus_link = clean_value(row.get('urlhaus_link', None))

            if not url_value:
                continue

            db_tags_list = []
            if threat_type and threat_type.lower() != "n/a":
                db_tags_list.append(f"threat: {threat_type}")

            if feed_tags and feed_tags.lower() != "n/a":
                for tag in feed_tags.split():
                    db_tags_list.append(f"tag: {tag}")

            if urlhaus_link and urlhaus_link.lower() != "n/a":
                db_tags_list.append(f"urlhaus_link- {urlhaus_link}")

            final_tags_for_db = ",".join(db_tags_list) if db_tags_list else None

            add_ioc(
                db_path=db_path,
                ioc_value=url_value,
                ioc_type='url',
                sources=source_name,
                feed_url=feed_url,
                first_seen_feed=date_added,
                tags=final_tags_for_db
            )

            processed_urls += 1

    except csv.Error as e:
        print(f"\nCSV DictReader error in {source_name}: {e}")
        return processed_urls

    except ValueError as e:
        print(f"\nAn unexpected error occurred processing {source_name} row: {e}")
        return processed_urls

    print(f"\nFinished processing {source_name}. Processed {processed_urls} URLs.")
    return processed_urls


def update_urlhaus(db_path=config.DATABASE_PATH, url=config.URLHAUS_URL):
    """Fetches and processes the URLhaus recent CSV feed."""
    print(f"Starting update for URLhaus from {url}...")

    feed_content = fetch_feed_content(url)
    if feed_content:
        print(f"Successfully fetched URLhaus feed ({len(feed_content)} bytes). Processing...")
        processed_count = process_urlhaus_feed(
            feed_content=feed_content,
            db_path=db_path,
            source_name=URLHAUS_SOURCE_NAME,
            feed_url=url
        )

    else:
        print("Failed to fetch URLhaus feed")


"""
===========================================================
OTX - AlienVault Pulse feed function

- AlienVault can be used both as a feed source (pulling lists of IOCs from "pulses") 
and an enrichment source (looking up a specific IOC).
===========================================================
"""

# Mapping from OTX indicator types to our internal types
OTX_TYPE_MAP = {
    "IPv4": "ipv4",
    "IPv6": "ipv6",
    "domain": "domain",
    "hostname": "domain",  # Treat hostname like domain
    "URL": "url",
    "FileHash-MD5": "md5",
    "FileHash-SHA1": "sha1",
    "FileHash-SHA256": "sha256",
    # Add more mappings as needed (e.g., CVE, email) later
}

OTX_SOURCE_NAME = "AlienVaultOTX"


def update_otx_feed(db_path=config.DATABASE_PATH, api_key=config.OTX_API_KEY):
    """Fetches recent pulses from AlienVault OTX and adds IOCs."""

    if not OTX_SDK_AVAILABLE:
        print("[!] Skipping OTX feed update: OTXv2 SDK not installed.")
        return 0

    if not api_key:
        print("[!] Skipping OTX feed update: OTX_API_KEY not configured.")
        return 0

    print(f"Starting update for {OTX_SOURCE_NAME}...")

    try:
        otx = OTXv2(api_key=api_key, user_agent=config.USER_AGENT)
        print(f"[*] Successfully connected to OTX API.")
    except Exception as e:
        print(f"[!] Failed to instantiate OTX client: {e}")
        return 0

    processed_iocs_count = 0
    pulses = []

    try:
        print("[*] Fetching recent pulses from OTX using getall()...")

        # --- Calculate 'modified_since' timestamp ---
        since_timestamp = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=100)

        print(f"[*] Fetching pulses modified since: {since_timestamp.strftime('%Y-%m-%d %H:%M:%S')}...")

        pulses = otx.getall(modified_since=since_timestamp.isoformat())  # Format for OTX API (ISO 8601 format)
        print(f"[*] Found {len(pulses)} pulses to process.")

    except Exception as e:
        print(f"[!] Error fetching pulses from OTX: {e}")
        return 0

    pbar = tqdm(pulses, total=len(pulses), desc=f"Processing {OTX_SOURCE_NAME}", unit="entries")
    for pulse in pbar:
        pulse_id_for_error = "UNKNOWN_ID"  # Default for error messages
        try:
            # --- Extract Pulse Context and Build Base Tags ---
            # Use .get() as pulse is likely a dictionary from the SDK's JSON parsing
            pulse_id = pulse.get('id')
            pulse_id_for_error = pulse_id if pulse_id else "UNKNOWN_ID"  # Update for specific error context
            pulse_name = pulse.get('name', 'N/A')
            pulse_modified = pulse.get('modified')
            pulse_adversary = pulse.get('adversary')
            pulse_tags_list = pulse.get('tags', [])  # OTX tags
            pulse_malware = pulse.get('malware_families', [])
            pulse_attack_ids = pulse.get('attack_ids', [])
            pulse_ref_url = f"https://otx.alienvault.com/pulse/{pulse_id}" if pulse_id else None

            # Prepare base tags list (formatted tags from pulse context)
            base_tags = []
            if pulse_name != 'N/A': base_tags.append(f"pulse_name:{pulse_name}")
            if pulse_adversary: base_tags.append(f"adversary:{pulse_adversary}")
            base_tags.extend([f"pulse_tag:{tag}" for tag in pulse_tags_list])
            base_tags.extend([f"malware:{fam}" for fam in pulse_malware])
            base_tags.extend([f"attack:{att_id}" for att_id in pulse_attack_ids])
            # --- End Base Tag Preparation ---

            indicators = pulse.get('indicators', [])
            if not indicators:
                continue  # Skip pulse if it has no indicators

            # --- Inner loop for indicators ---
            for indicator in indicators:
                ioc_value = indicator.get('indicator')
                otx_type_str = indicator.get('type')
                indicator_role = indicator.get('role')

                if not ioc_value or not otx_type_str:
                    continue  # Skip indicator if essential info missing

                # Map OTX type string to our internal type
                ioc_type = OTX_TYPE_MAP.get(otx_type_str)
                if not ioc_type:
                    continue  # Skip unsupported types

                # Build tags for this specific indicator
                current_indicator_tags = base_tags.copy()  # Start with base tags
                if indicator_role:
                    current_indicator_tags.append(f"role:{indicator_role}")
                final_tags_for_db = ",".join(current_indicator_tags)

                # Use pulse modified time as first_seen_feed
                first_seen = pulse_modified

                # Add the IOC to the database
                add_ioc(
                    db_path=db_path,
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    sources=OTX_SOURCE_NAME,
                    feed_url=pulse_ref_url,
                    first_seen_feed=first_seen,
                    tags=final_tags_for_db
                )
                processed_iocs_count += 1

        except Exception as e:
            # Catch errors during processing of a single pulse
            pbar.write(f"[!] Error processing pulse ID {pulse_id_for_error}: {e}")

    pbar.close()  # Close tqdm progress bar
    print(f"[*] Finished processing {OTX_SOURCE_NAME}. Added/updated approx {processed_iocs_count} IOCs.")  # Note: count includes updates/ignores
    return processed_iocs_count


if __name__ == "__main__":
    print(f"Running Feodo Tracker update directly. DB path: {config.DATABASE_PATH}")
    update_feodo_tracker()
    print("-" * 20)

    print(f"Running Malware Bazaar update directly. DB path: {config.DATABASE_PATH}")
    update_malware_bazaar()
    print("-" * 20)

    print(f"Running URLhaus update directly. DB path: {config.DATABASE_PATH}")
    update_urlhaus()
    print("-" * 20)

    print(f"Running OTX update directly. DB path: {config.DATABASE_PATH}")
    update_otx_feed(db_path=config.DATABASE_PATH, api_key=config.OTX_API_KEY)
    print("-" * 20)

    print("Feed handler testing finished.")
