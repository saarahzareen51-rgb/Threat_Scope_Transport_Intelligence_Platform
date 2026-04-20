import sqlite3

# Connect to your database
conn = sqlite3.connect("CTI2_Feeds.db")
cursor = conn.cursor()

# Example CVE to check
cve_id = "CVE-2024-12718"

cursor.execute(
    """
    SELECT cve_id, description, cvss_score, severity, attack_vector, attack_complexity, privileges_required, user_interaction, published_date, last_modified
    FROM cves
    WHERE cve_id = ?
""",
    (cve_id,),
)
cve_info = cursor.fetchone()
conn.close()

if not cve_info:
    print(f"{cve_id} not found in database")
else:
    print("CVE Info:")
    print(f"ID: {cve_info[0]}")
    print(f"Description: {cve_info[1]}")
    print(f"CVSS Score: {cve_info[2]}")
    print(f"Severity: {cve_info[3]}")
    print(f"Attack Vector: {cve_info[4]}")
    print(f"Attack Complexity: {cve_info[5]}")
    print(f"Privileges Required: {cve_info[6]}")
    print(f"User Interaction: {cve_info[7]}")
    print(f"Published Date: {cve_info[8]}")
    print(f"Last Modified: {cve_info[9]}")
