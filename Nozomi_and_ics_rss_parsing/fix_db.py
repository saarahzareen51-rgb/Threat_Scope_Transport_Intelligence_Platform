import sqlite3
import pandas as pd

DB_NAME = 'CTI2_Feeds.db'

# Connect to your database
conn = sqlite3.connect(DB_NAME)

# STEP 1: Find the bad entries first (check what we'll fix)
print("=== FINDING BAD ENTRIES ===")
bad_entries = pd.read_sql_query("""
    SELECT id, title, primary_sector, classify_method 
    FROM feed_entries 
    WHERE (title LIKE '%tarfile%' OR summary_clean LIKE '%tarfile%' OR summary LIKE '%tarfile%')
       OR (title LIKE '%Python%' AND primary_sector = 'Rail')
""", conn)

print("Bad entries found:")
print(bad_entries)
print()

# STEP 2: Fix them
print("=== CLEARING BAD CLASSIFICATIONS ===")
fixed_count = conn.execute("""
    UPDATE feed_entries 
    SET primary_sector='General', 
        sector_confidence=0.0, 
        is_transport=0,
        classify_method='unclassified',
        mitre_id='' 
    WHERE (title LIKE '%tarfile%' OR summary_clean LIKE '%tarfile%' OR summary LIKE '%tarfile%')
       OR (title LIKE '%Python%' AND primary_sector = 'Rail')
""").rowcount

conn.commit()
print(f"✅ FIXED {fixed_count} entries")

# STEP 3: Verify fix
print("\n=== VERIFICATION ===")
check = pd.read_sql_query("""
    SELECT id, title, primary_sector, classify_method 
    FROM feed_entries 
    WHERE title LIKE '%tarfile%' OR summary_clean LIKE '%tarfile%'
""", conn)
print("After fix:")
print(check)

conn.close()
print("\n🎉 DATABASE CLEANED! Restart your Streamlit app now.")
