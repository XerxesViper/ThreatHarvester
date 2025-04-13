import re
import requests
from db_manager import add_ioc

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"


def fetch_feed_content(url, timeout=30):
    """ Fetches the contents of a feed from a given URL. """
    try:
        response = requests.get(url, timeout=timeout, headers={'User-Agent': 'ThreatIntelTool/0.1'})
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


DEFAULT_DB_PATH = "../data/threat_intel.db"  # Adjust path relative to src/
DEFAULT_FEODO_URL = FEODO_URL


def update_feodo_tracker(db_path=DEFAULT_DB_PATH, url=DEFAULT_FEODO_URL):
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


if __name__ == "__main__":
    db_path_run = "data/threat_intel.db"

    print(f"Running Feodo Tracker update directly. DB path: {db_path_run}")
    update_feodo_tracker(db_path=db_path_run)
    print("Feodo Tracker update process finished.")
