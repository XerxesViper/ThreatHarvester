import sqlite3
import datetime
from . import config


def add_ioc(db_path, ioc_value, ioc_type, sources, feed_url=None, first_seen_feed=None, tags=None):
    connection = None

    try:
        connection = sqlite3.connect(db_path)
        cursor = connection.cursor()

        last_seen_local = datetime.datetime.now(datetime.timezone.utc).isoformat()
        sql = """
              INSERT INTO iocs
              (ioc_value, ioc_type, last_seen_local, sources, feed_url, first_seen_feed, tags)
              VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(ioc_value, ioc_type) DO
              UPDATE SET
                  last_seen_local = excluded.last_seen_local,
                  feed_url = excluded.feed_url; \
              """

        data = (ioc_value, ioc_type, last_seen_local, sources, feed_url, first_seen_feed, tags)
        cursor.execute(sql, data)
        connection.commit()

        # if cursor.rowcount > 0:
        #     print(f"New IOC added to database: {ioc_value} ({ioc_type}) - Debuglevel: 1")

    except sqlite3.Error as e:
        print(f"Error adding IOC to database [add_ioc]: {e}")

    finally:
        if connection:
            connection.close()


def add_iocs_batch(db_path, iocs_data):
    """
    Adds a batch of IOCs to the database using executemany.

    Args:
        db_path (str): Path to the SQLite database file.
        iocs_data (list): A list of tuples. Each tuple contains the data
                          for one IOC row in the correct column order:
                          (ioc_value, ioc_type, last_seen_local, sources,
                           feed_url, first_seen_feed, tags)
    """
    if not iocs_data:  # Do nothing if the list is empty
        return 0

    conn = None
    inserted_count = 0
    try:
        conn = sqlite3.connect(db_path, timeout=10.0)  # Increase timeout slightly for batch?
        cursor = conn.cursor()

        # Use INSERT OR IGNORE to handle duplicates based on primary key
        # Adjust column order if your original add_ioc used a different one
        sql = """
              INSERT \
              OR IGNORE INTO iocs 
        (ioc_value, ioc_type, last_seen_local, sources, feed_url, first_seen_feed, tags) 
        VALUES (?, ?, ?, ?, ?, ?, ?) \
              """

        # executemany inserts all rows in the list
        cursor.executemany(sql, iocs_data)
        inserted_count = cursor.rowcount  # Number of rows actually inserted/affected
        conn.commit()
        # print(f"[*] Batch insert: Attempted {len(iocs_data)}, Inserted/Ignored {inserted_count} IOCs.")

    except sqlite3.OperationalError as e:
        # Handle potential "database is locked" if another process interferes, though less likely now
        print(f"[!] Database error during batch insert: {e}")
        # Consider retry logic or raising the error
    except sqlite3.Error as e:
        print(f"[!] Database error during batch insert: {e}")
    finally:
        if conn:
            conn.close()

    return inserted_count  # Return rows actually inserted


def query_ioc(ioc_value):
    """Queries the local DB for an IOC value."""

    results = []
    connection = None
    try:
        connection = sqlite3.connect(config.DATABASE_PATH)
        cursor = connection.cursor()

        sql = "SELECT * FROM iocs WHERE ioc_value = ?"
        cursor.execute(sql, (ioc_value,))  # Pass value as a tuple

        rows = cursor.fetchall()  # Returns a list of sqlite3.row objects

        results = rows

        print(f"Found {len(results)} local record(s) for IOC: {ioc_value}")

    except sqlite3.Error as e:
        print(f"Error querying database for {ioc_value}: {e}")

    finally:
        if connection:
            connection.close()

    return results
