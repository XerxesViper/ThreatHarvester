import sqlite3

connection = sqlite3.connect('data/threat_intel.db')
cursor = connection.cursor()

# Define the CREATE TABLE statement
create_table_iocs = """
CREATE TABLE IF NOT EXISTS iocs (
    ioc_value TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    first_seen_feed TEXT,
    last_seen_local TEXT NOT NULL,
    sources TEXT NOT NULL,
    tags TEXT,
    feed_url TEXT,
    PRIMARY KEY (ioc_value, ioc_type)
    )
"""

create_table_feeds = """
CREATE TABLE IF NOT EXISTS feeds (
    feed_name TEXT PRIMARY KEY,
    feed_url TEXT,
    last_pull_time TEXT,
    status TEXT -- e.g., 'Success', 'Error: Connection Timeout'
)
"""

cursor.execute(create_table_iocs)
cursor.execute(create_table_feeds)

connection.commit()
connection.close()
