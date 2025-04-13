import sqlite3
import datetime


def add_ioc(db_path, ioc_value, ioc_type, sources, feed_url=None, first_seen_feed=None, tags=None):
    connection = None

    try:
        connection = sqlite3.connect(db_path)
        cursor = connection.cursor()

        last_seen_local = datetime.datetime.now(datetime.timezone.utc).isoformat()
        sql = """
        INSERT OR IGNORE INTO iocs 
        (ioc_value, ioc_type, last_seen_local, sources, feed_url, first_seen_feed, tags)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """

        data = (ioc_value, ioc_type, last_seen_local, sources, feed_url, first_seen_feed, tags)
        cursor.execute(sql, data)
        connection.commit()

        if cursor.rowcount > 0:
            print(f"New IOC added to database: {ioc_value} ({ioc_type}) - Debuglevel: 1")

    except sqlite3.Error as e:
        print(f"Error adding IOC to database [add_ioc]: {e}")

    finally:
        if connection:
            connection.close()