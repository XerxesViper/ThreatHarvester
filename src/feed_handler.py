import re
import io
import csv
import requests
import datetime
import ipaddress
from tqdm import tqdm

try:
    from OTXv2 import OTXv2

    OTX_SDK_AVAILABLE = True
except ImportError:
    print("[Warning] OTXv2 SDK not installed. OTX feed processing will be skipped.")
    OTX_SDK_AVAILABLE = False

try:
    from pymisp import PyMISP, MISPServerError  # Import PyMISP and common errors

    PYMISP_AVAILABLE = True
except ImportError:
    print("[Warning] pymisp library not installed. MISP feed processing will be skipped.")
    PYMISP_AVAILABLE = False

# Local Imports
from . import config
from .utils import IPV4_PATTERN, CIDR_PATTERN
from .db_manager import add_ioc, add_iocs_batch


def fetch_feed_content(url, timeout=30):
    """ Fetches the contents of a feed from a given URL. """

    user_agent = getattr(config, "USER_AGENT", 'ThreatIntelTool/0.3-TEST')

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
IP_PATTERN = IPV4_PATTERN


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

    ioc_batch = []
    batch_size = 1000
    total_added_count = 0

    try:
        last_seen_local = datetime.datetime.now(datetime.timezone.utc).isoformat()
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

            data_tuple = (url_value, "url", last_seen_local, source_name, url_value, date_added, final_tags_for_db)
            ioc_batch.append(data_tuple)
            # add_ioc(
            #     db_path=db_path,
            #     ioc_value=url_value,
            #     ioc_type='url',
            #     sources=source_name,
            #     feed_url=feed_url,
            #     first_seen_feed=date_added,
            #     tags=final_tags_for_db
            # )

            processed_urls += 1

            if len(ioc_batch) >= batch_size:
                total_added_count += add_iocs_batch(db_path, ioc_batch)
                ioc_batch = []  # Clear the batch

            # --- Insert any remaining items in the batch ---
        if ioc_batch:
            total_added_count += add_iocs_batch(db_path, ioc_batch)

        print(f"Processed {processed_urls} URLs from {source_name}. Processed {total_added_count} entries.")

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

    ioc_batch = []
    batch_size = 1000
    total_added_count = 0
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

            last_seen_local = datetime.datetime.now(datetime.timezone.utc).isoformat()

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
                data_tuple = (ioc_value, ioc_type, last_seen_local, OTX_SOURCE_NAME, pulse_ref_url, first_seen, final_tags_for_db)

                ioc_batch.append(data_tuple)
                # add_ioc(
                #     db_path=db_path,
                #     ioc_value=ioc_value,
                #     ioc_type=ioc_type,
                #     sources=OTX_SOURCE_NAME,
                #     feed_url=pulse_ref_url,
                #     first_seen_feed=first_seen,
                #     tags=final_tags_for_db
                # )
                processed_iocs_count += 1

        except Exception as e:
            # Catch errors during processing of a single pulse
            pbar.write(f"[!] Error processing pulse ID {pulse_id_for_error}: {e}")

        if len(ioc_batch) >= batch_size:
            total_added_count += add_iocs_batch(db_path, ioc_batch)
            ioc_batch = []  # Clear the batch

    # --- Insert any remaining items in the batch ---
    if ioc_batch:
        total_added_count += add_iocs_batch(db_path, ioc_batch)

    pbar.close()  # Close tqdm progress bar
    print(f"[*] Finished processing {OTX_SOURCE_NAME}. Added/updated approx {processed_iocs_count} IOCs.")  # Note: count includes updates/ignores
    return processed_iocs_count


"""
===========================================================
MISP feed functions

Multiple feeds are available (30+) for MISP. However the ones used here will
be the ones available in the official "feed format: misp" format.
===========================================================
"""
MISP_CIRCL_SOURCE_NAME = "MISP-CIRCL-OSINT"
misp_url = config.MISP_URL
misp_key = config.MISP_API_KEY
misp_verifycert = config.MISP_VERIFYCERT

# --- Type Mapping ---
# We'll need a MISP attribute type map later
MISP_TYPE_MAP = {
    "ip-src": "ipv4",
    "ip-dst": "ipv4",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "filename": "filename",  # Example new type
    "regkey": "regkey",  # Example new type
    "user-agent": "user-agent",  # Example new type
    # Add more MISP attribute types as needed
}

# def update_misp_feed(
#         db_path=config.DATABASE_PATH,
#         misp_url=config.MISP_URL,
#         misp_key=config.MISP_API_KEY,
#         verify_cert=config.MISP_VERIFYCERT,
#         source_name=MISP_CIRCL_SOURCE_NAME,
#         time_filter_days=1
# ):
#     """
#     Connects to MISP, fetches recent EVENTS via direct API POST,
#     extracts attributes, and adds them to the local database.
#     """
#     # --- Initial Checks ---
#     if not PYMISP_AVAILABLE: return 0
#     if not misp_url: return 0
#     if not misp_key: return 0
#
#     print(f"Attempting to connect to MISP instance at {misp_url}...")
#
#     # --- Initialize PyMISP Client (Still useful for connection check/auth) ---
#     misp = None
#     try:
#         misp = PyMISP(misp_url, misp_key, verify_cert, 'json')
#         version_info = misp.misp_instance_version
#         if not version_info or 'version' not in version_info:
#             print("[!] Connected, but failed to get MISP version.")
#             return 0
#         print(f"[*] Successfully connected! MISP Version: {version_info.get('version')}")
#     except Exception as e:
#         print(f"[!] Failed to initialize PyMISP client for {misp_url}: {e}")
#         return 0
#
#         # --- Search for Recent EVENTS via direct_call POST ---
#     processed_iocs_count = 0
#     recent_events_response = None
#     try:
#         # --- Calculate timestamp ---
#         time_delta = datetime.timedelta(days=time_filter_days)
#         since_timestamp = datetime.datetime.now(datetime.timezone.utc) - time_delta
#         # Use epoch timestamp as string in payload
#         timestamp_filter = str(int(since_timestamp.timestamp()))
#
#         print(f"[*] Searching MISP via POST for events published since timestamp: {timestamp_filter} ({since_timestamp.isoformat()})...")
#
#         # --- Define POST payload ---
#         # Key is likely 'publish_timestamp' for event searching
#         payload = {
#             "returnFormat": "json",
#             "publish_timestamp": timestamp_filter,
#             # Add other event filters here if needed, e.g., "orgc": "CIRCL"
#         }
#
#         # --- Use direct_call (implicitly POSTs when data is provided) ---
#         api_path = 'events/restSearch'
#         recent_events_response = misp.direct_call(api_path, payload)
#
#         # --- DEBUG: Inspect the direct_call response ---
#         print("-" * 20)
#         print(f"DEBUG: MISP direct_call response type: {type(recent_events_response)}")
#         print(f"DEBUG: MISP direct_call response data (first 500 chars): {str(recent_events_response)[:500]}")
#         print("-" * 20)
#         # --- END DEBUG ---
#
#         # --- Extract the list of events ---
#         # Response structure is often {'response': [list of event dicts]}
#         if isinstance(recent_events_response, dict):
#             # Check the 'response' key first
#             recent_events = recent_events_response.get('response', [])
#             # If not found, maybe the response itself is the list (less common)
#             if not recent_events and isinstance(recent_events_response.get('Event'), list):
#                 recent_events = recent_events_response.get('Event', [])
#             elif not recent_events:
#                 # Check if the response contains errors reported by the API
#                 if 'errors' in recent_events_response:
#                     print(f"[!] MISP API returned errors: {recent_events_response['errors']}")
#                 elif 'message' in recent_events_response:  # Another common error format
#                     print(f"[!] MISP API returned message: {recent_events_response['message']}")
#                 else:
#                     print("[!] Could not find event list in MISP response key ('response').")
#                 recent_events = []  # Ensure it's a list
#         else:
#             print(f"[!] MISP direct_call did not return a dictionary. Response: {recent_events_response}")
#             recent_events = []
#
#         print(f"[*] Found {len(recent_events)} recent MISP events to process.")
#
#     except MISPServerError as e:
#         print(f"[!] MISP Server Error during event direct_call: {e}")
#         return 0
#     except Exception as e:
#         print(f"[!] Error during MISP event direct_call or initial parsing: {e}")
#         return 0
#
#         # --- Process Attributes within Events (using dictionaries) ---
#     if not recent_events:
#         print("[*] No recent events found matching the criteria.")
#     else:
#         pbar_event = tqdm(recent_events, desc=f"Processing {source_name} Events", unit="event", leave=False)
#         for event_dict in pbar_event:  # Events are now dictionaries
#             event_id = event_dict.get('id', 'N/A')
#             pbar_event.set_postfix(event_id=event_id)
#
#             # Attributes are likely under the 'Attribute' key within the event dict
#             attributes_in_event = event_dict.get('Attribute', [])
#             if not attributes_in_event:
#                 continue
#
#                 # Get event tags (likely under 'Tag' key)
#             event_tags_list = event_dict.get('Tag', [])
#
#             # Inner loop for attributes (which are also dictionaries)
#             for attribute_dict in attributes_in_event:
#                 try:
#                     # Access data using dictionary .get()
#                     ioc_value = attribute_dict.get('value')
#                     misp_type = attribute_dict.get('type')
#                     if not ioc_value or not misp_type: continue
#
#                     ioc_type = MISP_TYPE_MAP.get(misp_type)
#                     if not ioc_type: continue
#
#                     attr_timestamp_val = attribute_dict.get('timestamp')
#                     first_seen = None
#                     if attr_timestamp_val:
#                         try:
#                             ts_epoch = int(float(attr_timestamp_val))
#                             first_seen = datetime.datetime.fromtimestamp(ts_epoch, tz=datetime.timezone.utc).isoformat()
#                         except (ValueError, TypeError):
#                             first_seen = str(attr_timestamp_val)
#
#                     # Get attribute tags (likely under 'Tag' key within attribute dict)
#                     attribute_tags_list = attribute_dict.get('Tag', [])
#
#                     current_tags = []
#                     if event_id != 'N/A': current_tags.append(f"misp_event_id:{event_id}")
#                     current_tags.extend([f"misp_attr_tag:{tag.get('name')}" for tag in attribute_tags_list if isinstance(tag, dict) and tag.get('name')])
#                     current_tags.extend([f"misp_event_tag:{tag.get('name')}" for tag in event_tags_list if isinstance(tag, dict) and tag.get('name')])
#                     current_tags.append(f"misp_type:{misp_type}")
#                     final_tags_for_db = ",".join(current_tags)
#
#                     ref_url = f"{misp_url.rstrip('/')}/events/view/{event_id}" if event_id != 'N/A' and misp_url else None
#
#                     add_ioc(
#                         db_path=db_path, ioc_value=ioc_value, ioc_type=ioc_type,
#                         sources=source_name, feed_url=ref_url,
#                         first_seen_feed=first_seen, tags=final_tags_for_db
#                     )
#                     processed_iocs_count += 1
#
#                 except Exception as e:
#                     attr_uuid = attribute_dict.get('uuid', 'UNKNOWN_UUID')
#                     pbar_event.write(f"[!] Error processing MISP attribute UUID {attr_uuid} in event {event_id}: {e}")
#                     continue
#         pbar_event.close()
#
#     print(f"[*] Finished processing {source_name}. Added/updated approx {processed_iocs_count} IOCs.")
#     return processed_iocs_count

"""
===========================================================
FIREHOL feed functions

Multiple .netset files are available for FireHOL. However here I will be using
the most relevant one for the Threat Intel Feed Correlator.
===========================================================
"""

FIREHOL_L1_SOURCE_NAME = "FireHOL_Level1"


def process_firehol_feed(feed_content, db_path, source_name, feed_url=None, batch_size=1000):  # Add batch_size
    """ Parses FireHOL feed, batches IOCs, and inserts them. """
    if not feed_content: return 0

    processed_lines = 0
    total_added_count = 0
    lines = feed_content.strip().splitlines()
    ioc_batch = []  # Initialize batch list

    print(f"[*] Processing {source_name} feed...")
    pbar = tqdm(lines, desc=f"Processing {source_name}", unit="IPs", leave=True)

    for line in pbar:
        entry = line.strip()
        processed_lines += 1
        if not entry or entry.startswith('#'): continue

        # --- Prepare data tuple (common part) ---
        last_seen_local = datetime.datetime.now(datetime.timezone.utc).isoformat()
        # Default values for fields not present in FireHOL
        first_seen_feed = None
        tags = None

        # --- Handle CIDR ---
        if CIDR_PATTERN.match(entry):
            try:
                network = ipaddress.ip_network(entry, strict=False)
                if network.version != 4: continue

                if network.num_addresses <= 256:
                    tags = f"cidr_source:{entry}"  # Add tag for expanded IPs
                    for ip_obj in network.hosts():
                        ioc_value = str(ip_obj)
                        ioc_type = 'ipv4'
                        # Prepare tuple in correct order for add_iocs_batch
                        data_tuple = (ioc_value, ioc_type, last_seen_local, source_name, feed_url, first_seen_feed, tags)
                        ioc_batch.append(data_tuple)
                else:
                    ioc_value = entry
                    ioc_type = 'cidr'
                    tags = None  # No extra tag for large CIDR itself
                    data_tuple = (ioc_value, ioc_type, last_seen_local, source_name, feed_url, first_seen_feed, tags)
                    ioc_batch.append(data_tuple)

            except Exception as e:
                pbar.write(f"[!] Error processing CIDR line {entry} in {source_name}: {e}")
                continue

        # --- Handle IPv4 ---
        elif IPV4_PATTERN.match(entry):
            ioc_value = entry
            ioc_type = 'ipv4'
            tags = None
            data_tuple = (ioc_value, ioc_type, last_seen_local, source_name, feed_url, first_seen_feed, tags)
            ioc_batch.append(data_tuple)

        # --- Skip other lines ---
        else:
            continue

            # --- Insert batch if size reached ---
        if len(ioc_batch) >= batch_size:
            total_added_count += add_iocs_batch(db_path, ioc_batch)
            ioc_batch = []  # Clear the batch

    # --- Insert any remaining items in the batch ---
    if ioc_batch:
        total_added_count += add_iocs_batch(db_path, ioc_batch)

    pbar.close()
    print(f"[*] Finished processing {source_name}. Processed {processed_lines} lines. Added/updated approx {total_added_count} IOCs.")
    return total_added_count  # Return number of IOCs actually inserted/ignored


def update_all_firehol_feeds(db_path=config.DATABASE_PATH):
    """Fetches and processes all FireHOL feeds defined in config.FIREHOL_FEEDS."""

    print("\n" + "-" * 10 + " Starting FireHOL Feed Updates " + "-" * 10)
    total_processed_count = 0

    # Check if the config dictionary exists and is not empty
    if not hasattr(config, 'FIREHOL_FEEDS') or not config.FIREHOL_FEEDS:
        print("[!] No FireHOL feeds defined in config.FIREHOL_FEEDS dictionary. Skipping.")
        return 0

    feed_count = len(config.FIREHOL_FEEDS)
    processed_feed_num = 0

    for feed_key, feed_url in config.FIREHOL_FEEDS.items():
        processed_feed_num += 1
        # Construct source name dynamically
        source_name = f"FireHOL_{feed_key.replace('_', '-')}"  # Ensure clean name
        print(f"\n[{processed_feed_num}/{feed_count}] Starting update for {source_name} from {feed_url}...")

        if not feed_url:
            print(f"[*] Skipping {source_name}: URL not configured.")
            continue

        feed_content = fetch_feed_content(feed_url)
        if feed_content:
            # Use the updated processor
            processed_count = process_firehol_feed(
                feed_content=feed_content,
                db_path=db_path,
                source_name=source_name,
                feed_url=feed_url
            )
            total_processed_count += processed_count
        else:
            print(f"[!] Failed to fetch {source_name} feed.")

    print("\n" + "-" * 10 + f" Finished FireHOL Feed Updates. Processed approx {total_processed_count} IOCs across {feed_count} feeds." + "-" * 10)
    return total_processed_count


"""
===========================================================
IPSUM feed functions

https://github.com/stamparm/ipsum
===========================================================
"""
IPSUM_SOURCE_NAME = "IPsum"


def process_ipsum_feed(feed_content, db_path, source_name=IPSUM_SOURCE_NAME, feed_url=None, batch_size=1000):
    """Parses IPsum feed (IP<tab>Count) and adds IOCs with tags."""
    if not feed_content:
        print(f"No content received for {source_name}, skipping processing.")
        return 0

    processed_lines = 0
    total_added_count = 0
    lines = feed_content.strip().splitlines()
    ioc_batch = []

    print(f"[*] Processing {source_name} feed...")
    pbar = tqdm(lines, desc=f"Processing {source_name}", unit="line", leave=True)

    for line in pbar:
        processed_lines += 1
        entry = line.strip()
        if not entry or entry.startswith('#'):
            continue

        parts = entry.split('\t')  # Split by tab
        if len(parts) != 2:
            # pbar.write(f"Skipping malformed line in {source_name}: {entry}")
            continue

        ip_value = parts[0].strip()
        count_str = parts[1].strip()

        # Validate IP
        if not IPV4_PATTERN.match(ip_value):
            # pbar.write(f"Skipping non-IPv4 value in {source_name}: {ip_value}")
            continue

        # Validate and get count for tag
        report_count = None
        try:
            report_count = int(count_str)
        except ValueError:
            # pbar.write(f"Skipping line with non-integer count in {source_name}: {entry}")
            continue

        # Prepare data for batch insert
        ioc_type = 'ipv4'
        last_seen_local = datetime.datetime.now(datetime.timezone.utc).isoformat()
        first_seen_feed = None  # No timestamp in feed
        tags = f"ipsum_reports:{report_count}"  # Add count as tag

        data_tuple = (ip_value, ioc_type, last_seen_local, source_name, feed_url, first_seen_feed, tags)
        ioc_batch.append(data_tuple)

        # Insert batch if size reached
        if len(ioc_batch) >= batch_size:
            total_added_count += add_iocs_batch(db_path, ioc_batch)
            ioc_batch = []  # Clear the batch

    # Insert any remaining items
    if ioc_batch:
        total_added_count += add_iocs_batch(db_path, ioc_batch)

    pbar.close()
    print(f"[*] Finished processing {source_name}. Processed {processed_lines} lines. Added/updated approx {total_added_count} IOCs.")
    return total_added_count


def update_ipsum_feed(db_path=config.DATABASE_PATH):
    """Fetches and processes the IPsum feed."""
    source_name = IPSUM_SOURCE_NAME
    feed_key = "ipsum"  # Key used in config.OTHER_FEEDS

    # Get URL from the config dictionary
    feed_url = config.OTHER_FEEDS.get(feed_key)

    if not feed_url:
        print(f"[!] Skipping {source_name}: URL not found in config.OTHER_FEEDS['{feed_key}']")
        return 0

    print(f"\nStarting update for {source_name} from {feed_url}...")
    feed_content = fetch_feed_content(feed_url)
    if feed_content:
        print(f"[*] Successfully fetched {source_name} feed ({len(feed_content)} bytes). Processing...")
        process_ipsum_feed(  # Use the specific processor
            feed_content=feed_content,
            db_path=db_path,
            source_name=source_name,
            feed_url=feed_url
        )
    else:
        print(f"[!] Failed to fetch {source_name} feed.")

    return None


if __name__ == "__main__":
    # print(f"Running Feodo Tracker update directly. DB path: {config.DATABASE_PATH}")
    # update_feodo_tracker()
    # print("-" * 20)
    #
    # print(f"Running Malware Bazaar update directly. DB path: {config.DATABASE_PATH}")
    # update_malware_bazaar()
    # print("-" * 20)
    #
    # print(f"Running URLhaus update directly. DB path: {config.DATABASE_PATH}")
    # update_urlhaus()
    # print("-" * 20)
    # #
    # print(f"Running OTX update directly. DB path: {config.DATABASE_PATH}")
    # update_otx_feed(db_path=config.DATABASE_PATH, api_key=config.OTX_API_KEY)
    # print("-" * 20)

    # print(f"Running MISP update directly. DB path: {config.DATABASE_PATH}")
    # update_misp_feed(db_path=config.DATABASE_PATH, misp_url=config.MISP_URL, misp_key=config.MISP_API_KEY, verify_cert=config.MISP_VERIFYCERT, source_name="MISP-Instance")
    # print("-" * 20)

    # print(f"Running FireHOL update directly. DB path: {config.DATABASE_PATH}")
    # update_all_firehol_feeds(db_path=config.DATABASE_PATH)
    # print("-" * 20)

    print(f"Running IPSUM update directly. DB path: {config.DATABASE_PATH}")
    update_ipsum_feed(db_path=config.DATABASE_PATH)
    print("-" * 20)

    print("Feed handler testing finished.")
