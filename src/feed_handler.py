import re
import io
import csv
import requests
from tqdm import tqdm

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
                db_tags_list.append(f"signature:{signature}")

            # Add file type
            if file_type and file_type.lower() not in ["", "n/a"]:
                db_tags_list.append(f"file_type:{file_type}")

            # Add mime type
            if mime_type and mime_type.lower() not in ["", "n/a"]:
                db_tags_list.append(f"mime:{mime_type}")

            # Optional: Add filename if present and meaningful
            if file_name and file_name.lower() not in ["", "n/a"]:
                db_tags_list.append(f"filename:{file_name}")

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


if __name__ == "__main__":

    db_path_run = config.DATABASE_PATH

    # --- Test Feodo Tracker ---
    print(f"Running Feodo Tracker update directly. DB path: {config.DATABASE_PATH}")
    update_feodo_tracker(db_path=db_path_run)
    print("-" * 20)  # Separator

    # --- Test Malware Bazaar ---
    print(f"Running Malware Bazaar update directly. DB path: {config.DATABASE_PATH}")
    update_malware_bazaar(db_path=db_path_run)
    print("-" * 20)  # Separator

    print("Feed handler testing finished.")
