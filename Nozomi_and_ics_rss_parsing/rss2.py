import sqlite3  # Carry out all database operations
import feedparser  # Parse RSS feeds from various sources
import time  # Time functions for scheduling and timestamps
import schedule
import re  # Regular expressions
import requests
from datetime import datetime
from email.utils import (
    parsedate_to_datetime,
)  # Parse email date formats into datetime objects
from html import unescape  # Unescape HTML entities in text
from html.parser import HTMLParser
from flask import (
    Flask,
    jsonify,
    render_template,
)  # Flask web framework for dashboard and API endpoints


# ---------------------------------
# HTML STRIPPING-:
# Remove HTML tags from text
## Initialize the parent HTMLParser class
# Reset the parser state to a clean slate
# Disable strict HTML parsing (tolerates malformed HTML)
# Automatically convert character references to Unicode
# List to accumulate extracted text fragments
# -----------------------------------
class HTMLStripper(HTMLParser):
    """Remove HTML tags from text"""

    def __init__(self):
        super().__init__()
        self.reset()
        self.strict = False
        self.convert_charrefs = True
        self.text = []

    def handle_data(self, d):
        self.text.append(d)

    def get_data(self):
        return "".join(self.text)


def strip_html_tags(html):
    s = HTMLStripper()
    s.feed(html)
    return s.get_data()


# ----------------------
# SEVERITY CLASSIFICATION
# ----------------------
def classify_severity(title, summary):
    text = (title + " " + summary).lower()
    if any(
        word in text
        for word in [
            "critical",
            "zero-day",
            "0-day",
            "rce",
            "remote code execution",
            "authentication bypass",
            "unauthenticated",
            "wormable",
        ]
    ):
        return "CRITICAL"
    elif any(
        word in text
        for word in [
            "high",
            "exploit",
            "vulnerability",
            "injection",
            "overflow",
            "arbitrary code",
            "privilege escalation",
            "backdoor",
        ]
    ):
        return "HIGH"
    elif any(
        word in text
        for word in [
            "medium",
            "moderate",
            "update",
            "patch",
            "disclosure",
            "information leak",
            "denial of service",
            "ddos",
        ]
    ):
        return "MEDIUM"
    else:
        return "LOW"


# ----------------------
# THREAT CATEGORIZATION
# ----------------------
def categorize_threat(title, summary):
    text = (title + " " + summary).lower()
    categories = []
    if any(word in text for word in ["ransomware", "crypto", "locker", "encryp"]):
        categories.append("Ransomware")
    if any(
        word in text
        for word in ["phishing", "spear-phishing", "email", "social engineering"]
    ):
        categories.append("Phishing")
    if any(
        word in text
        for word in [
            "ics",
            "scada",
            "plc",
            "industrial",
            "operational technology",
            "ot",
        ]
    ):
        categories.append("ICS/OT")
    if any(word in text for word in ["malware", "trojan", "backdoor", "rat", "botnet"]):
        categories.append("Malware")
    if any(word in text for word in ["ddos", "denial of service", "dos attack"]):
        categories.append("DDoS")
    if any(
        word in text
        for word in ["sql injection", "xss", "csrf", "cross-site", "web application"]
    ):
        categories.append("Web Attack")
    if any(
        word in text
        for word in ["apt", "advanced persistent", "nation-state", "state-sponsored"]
    ):
        categories.append("APT")
    return ",".join(categories) if categories else "General"


# ----------------------
# IOC EXTRACTION
# ----------------------
def extract_iocs(text):
    iocs = {"cves": [], "ips": [], "domains": [], "hashes": []}
    iocs["cves"] = list(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)))
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    iocs["ips"] = list(
        set(
            [ip for ip in ips if all(0 <= int(octet) <= 255 for octet in ip.split("."))]
        )
    )
    iocs["domains"] = list(
        set(
            re.findall(
                r"\b[a-z0-9-]+\.(?:com|net|org|gov|edu|io|co)\b", text, re.IGNORECASE
            )
        )
    )
    iocs["hashes"] = list(set(re.findall(r"\b[a-fA-F0-9]{32,64}\b", text)))
    return iocs


# ----------------------
# TRANSPORT RELEVANCE & OT MAPPING
# ----------------------
def is_transport_relevant(title, summary):
    text = (title + " " + summary).lower()
    transport_keywords = [
        "rail",
        "metro",
        "train",
        "signaling",
        "station",
        "rolling stock",
        "traffic",
        "control room",
    ]
    ot_protocols = ["plc", "scada", "hmi", "modbus", "dnp3", "opc ua", "profinet"]
    return (
        "Yes"
        if any(word in text for word in transport_keywords + ot_protocols)
        else "No"
    )


def map_to_ot_assets(title, summary):
    text = (title + " " + summary).lower()
    assets = []
    if any(word in text for word in ["plc", "scada", "hmi"]):
        assets.append("Control/SCADA/PLC")
    if any(word in text for word in ["modbus", "dnp3", "opc ua", "profinet"]):
        assets.append("Industrial Network/Protocol")
    if any(word in text for word in ["rail", "metro", "train", "signaling"]):
        assets.append("Transport OT Asset")
    return ", ".join(assets) if assets else "General OT"


# ----------------------
# STORAGE CLASS-:
# Store database filename as instance variable
# Immediately create tables when a storage instance is created
# ----------------------
class storage:
    def __init__(self, db_name="CTI2_Feeds.db"):
        self.db_name = db_name
        self.creating_tables()

    def creating_tables(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS feed_entries (
                id TEXT PRIMARY KEY,
                source TEXT,
                title TEXT,
                summary TEXT,
                summary_clean TEXT,
                link TEXT,
                published TEXT,
                published_timestamp TEXT,
                author TEXT,
                tags TEXT,
                severity TEXT,
                category TEXT,
                transport_relevance TEXT,
                mapped_assets TEXT,
                collected_at TEXT
            )
        """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id TEXT,
                ioc_type TEXT,
                ioc_value TEXT,
                FOREIGN KEY (entry_id) REFERENCES feed_entries(id)
            )
        """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL,
                severity TEXT,
                attack_vector TEXT,
                attack_complexity TEXT,
                privileges_required TEXT,
                user_interaction TEXT,
                cwe_id TEXT,
                published_date TEXT,
                last_modified TEXT
            )
        """
        )

        conn.commit()
        conn.close()

    def get_feed(self, url):
        try:
            return feedparser.parse(url)
        except Exception as e:
            print(f"Error fetching feed: {e}")
            return None

    def check_feed(self, url, feed_name="Feed"):
        timestamp = time.strftime("%H:%M:%S")
        print(f"[{timestamp}] Checking for new threats...")

        feed = self.get_feed(url)
        if not feed or not feed.get("entries"):
            print("No Entries Found!")
            return 0

        new_count = 0
        total = len(feed.entries)

        for entry in feed.entries:
            id_of_entry = entry.get("id", entry.get("link", ""))
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM feed_entries WHERE id = ?", (id_of_entry,))
            exists = cursor.fetchone()

            if not exists:
                title = entry.get("title", "No title")
                summary = entry.get("summary", "")
                link = entry.get("link", "")
                published = entry.get("published", "")

                summary_clean = strip_html_tags(summary)
                summary_clean = unescape(summary_clean)
                summary_clean = " ".join(summary_clean.split())

                severity = classify_severity(title, summary_clean)
                category = categorize_threat(title, summary_clean)
                transport_relevance = is_transport_relevant(title, summary_clean)
                mapped_assets = map_to_ot_assets(title, summary_clean)

                published_timestamp = ""
                try:
                    if published:
                        dt = parsedate_to_datetime(published)
                        published_timestamp = dt.isoformat()
                except:
                    published_timestamp = datetime.now().isoformat()

                author = entry.get("author", "")
                tags = ",".join([tag.get("term", "") for tag in entry.get("tags", [])])
                collected_at = datetime.now().isoformat()

                iocs = extract_iocs(title + " " + summary_clean)

                cursor.execute(
                    """
                    INSERT INTO feed_entries 
                    (id, source, title, summary, summary_clean, link, published, published_timestamp, 
                     author, tags, severity, category, transport_relevance, mapped_assets, collected_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        id_of_entry,
                        feed_name,
                        title,
                        summary,
                        summary_clean,
                        link,
                        published,
                        published_timestamp,
                        author,
                        tags,
                        severity,
                        category,
                        transport_relevance,
                        mapped_assets,
                        collected_at,
                    ),
                )

                for cve in iocs["cves"]:
                    cursor.execute(
                        "INSERT INTO iocs (entry_id, ioc_type, ioc_value) VALUES (?, ?, ?)",
                        (id_of_entry, "CVE", cve),
                    )
                for ip in iocs["ips"]:
                    cursor.execute(
                        "INSERT INTO iocs (entry_id, ioc_type, ioc_value) VALUES (?, ?, ?)",
                        (id_of_entry, "IP", ip),
                    )
                for domain in iocs["domains"]:
                    cursor.execute(
                        "INSERT INTO iocs (entry_id, ioc_type, ioc_value) VALUES (?, ?, ?)",
                        (id_of_entry, "DOMAIN", domain),
                    )
                for hash_val in iocs["hashes"]:
                    cursor.execute(
                        "INSERT INTO iocs (entry_id, ioc_type, ioc_value) VALUES (?, ?, ?)",
                        (id_of_entry, "HASH", hash_val),
                    )

                conn.commit()
                print(
                    f"  ✓ NEW: [{severity}] {title} | Transport: {transport_relevance} | OT Assets: {mapped_assets}"
                )
                new_count += 1

            conn.close()

        if new_count > 0:
            print(f"  → Saved {new_count} new threat(s) from {total} total entries")
        else:
            print(f"  → No new threats (checked {total} entries)")

        return new_count

    def recent_entries(self, limit=5, source=None):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        if source:
            cursor.execute(
                """
                SELECT source, title, published, link, summary_clean, severity, category, transport_relevance, mapped_assets 
                FROM feed_entries 
                WHERE source = ?
                ORDER BY published_timestamp DESC
                LIMIT ?
            """,
                (source, limit),
            )
        else:
            cursor.execute(
                """
                SELECT source, title, published, link, summary_clean, severity, category, transport_relevance, mapped_assets 
                FROM feed_entries 
                ORDER BY published_timestamp DESC
                LIMIT ?
            """,
                (limit,),
            )

        entries = cursor.fetchall()
        conn.close()

        if not entries:
            print("\nNo entries in database yet")
            return

        print(f"\n{'='*80}")
        if source:
            print(f"Recent Updates from {source} (showing {len(entries)} entries)")
        else:
            print(
                f"Recent CTI Updates from All Sources (showing {len(entries)} entries)"
            )
        print(f"{'='*80}\n")

        for i, (
            src,
            title,
            published,
            link,
            summary,
            severity,
            category,
            transport_relevance,
            mapped_assets,
        ) in enumerate(entries, 1):
            print(f"[{i}] [{src}] [{severity}] {title}")
            print(f"    Category: {category}")
            print(f"    Transport Relevant: {transport_relevance}")
            print(f"    OT Assets: {mapped_assets}")
            print(f"    Published: {published}")
            print(f"    Link: {link}")
            if summary:
                print(f"    Summary: {summary[:150]}...")
            print()

    def get_stats(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM feed_entries")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT source, COUNT(*) FROM feed_entries GROUP BY source")
        by_source = cursor.fetchall()

        cursor.execute("SELECT severity, COUNT(*) FROM feed_entries GROUP BY severity")
        by_severity = cursor.fetchall()

        cursor.execute(
            "SELECT category, COUNT(*) FROM feed_entries GROUP BY category ORDER BY COUNT(*) DESC LIMIT 5"
        )
        top_categories = cursor.fetchall()

        cursor.execute("SELECT COUNT(*) FROM iocs")
        total_iocs = cursor.fetchone()[0]

        cursor.execute("SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type")
        by_ioc_type = cursor.fetchall()

        cursor.execute(
            "SELECT published FROM feed_entries ORDER BY published_timestamp DESC LIMIT 1"
        )
        latest = cursor.fetchone()
        latest_date = latest[0] if latest else "N/A"

        conn.close()

        print(f"\n{'='*80}")
        print("DATABASE STATISTICS")
        print(f"{'='*80}")
        print(f"Total Threats: {total}")

        print(f"\nBy Source:")
        for source, count in by_source:
            print(f"  • {source}: {count}")

        print(f"\nBy Severity:")
        for severity, count in by_severity:
            print(f"  • {severity}: {count}")

        print(f"\nTop Categories:")
        for category, count in top_categories:
            print(f"  • {category}: {count}")

        print(f"\nExtracted IOCs:")
        print(f"  Total: {total_iocs}")
        for ioc_type, count in by_ioc_type:
            print(f"    • {ioc_type}: {count}")

        print(f"\nLatest update: {latest_date}")
        print(f"Database file: {self.db_name}")
        print(f"{'='*80}\n")

    def get_iocs_for_threat(self, entry_id):
        """Get all IOCs for a specific threat"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT ioc_type, ioc_value FROM iocs WHERE entry_id = ?", (entry_id,)
        )
        iocs = cursor.fetchall()
        conn.close()

        return iocs

    # ----------------------------------------

    def enrich_cve_from_nvd(self, cve_id, api_key):
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        headers = {"apiKey": api_key}

        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code != 200:
                print(f"Failed to fetch {cve_id}: {response.status_code}")
                return

            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                print(f"No vulnerability data for {cve_id}")
                return

            cve = vulns[0]["cve"]
            description = (
                cve["descriptions"][0]["value"] if cve.get("descriptions") else None
            )

            metrics = cve.get("metrics", {})
            cvss_block = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
            cvss = cvss_block[0]["cvssData"] if cvss_block else {}

            published_date = cve.get("published")
            last_modified = cve.get("lastModified")

            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR IGNORE INTO cves
                (cve_id, description, cvss_score, severity,
                attack_vector, attack_complexity, privileges_required,
                user_interaction, cwe_id, published_date, last_modified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    cve_id,
                    description,
                    cvss.get("baseScore") if cvss else None,
                    cvss.get("baseSeverity") if cvss else None,
                    cvss.get("attackVector") if cvss else None,
                    cvss.get("attackComplexity") if cvss else None,
                    cvss.get("privilegesRequired") if cvss else None,
                    cvss.get("userInteraction") if cvss else None,
                    None,
                    published_date,
                    last_modified,
                ),
            )
            conn.commit()
            conn.close()
            print(f"✓ Enriched {cve_id}")

        except Exception as e:
            print(f"CVE error {cve_id}: {e}")

    # -------------------------------------------------
    def re_enrich_all_cves(self, api_key):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        # Get ALL CVEs from iocs — not just unenriched ones
        cursor.execute(
            """
            SELECT DISTINCT ioc_value
            FROM iocs
            WHERE ioc_type = 'CVE'
        """
        )
        cves = cursor.fetchall()
        conn.close()

        print(f"Re-enriching {len(cves)} CVEs with real NVD severity...")

        for (cve_id,) in cves:
            self.enrich_cve_from_nvd(cve_id, api_key)
            time.sleep(6)  # NVD rate limit

        print("Done. All severities updated from NVD CVSS scores.")

    def enrich_all_cves(self, api_key):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT DISTINCT ioc_value
            FROM iocs
            WHERE ioc_type = 'CVE'
            AND ioc_value NOT IN (SELECT cve_id FROM cves)
        """
        )

        cves = cursor.fetchall()
        conn.close()

        for (cve_id,) in cves:
            self.enrich_cve_from_nvd(cve_id, api_key)
            time.sleep(6)  # NVD rate limit


# ----------------------
# FLASK ENDPOINTS
# ----------------------
app = Flask(__name__)
collector = storage(db_name="CTI2_Feeds.db")  # reuse the storage class


@app.route("/")
def dashboard():
    return render_template("index.html")  # dashboard HTML in templates/


@app.route("/api/active")
def active_threats():
    conn = sqlite3.connect(collector.db_name)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, title, severity, category, transport_relevance, mapped_assets, published
        FROM feed_entries
        ORDER BY published_timestamp DESC
        LIMIT 20
    """
    )
    rows = cursor.fetchall()
    conn.close()
    data = [
        {
            "id": r[0],
            "title": r[1],
            "severity": r[2],
            "category": r[3],
            "transport_relevance": r[4],
            "mapped_assets": r[5],
            "published": r[6],
        }
        for r in rows
    ]
    return jsonify(data)


@app.route("/api/severity")
def severity_counts():
    conn = sqlite3.connect(collector.db_name)
    cursor = conn.cursor()
    cursor.execute("SELECT severity, COUNT(*) FROM feed_entries GROUP BY severity")
    rows = cursor.fetchall()
    conn.close()
    data = {r[0]: r[1] for r in rows}
    return jsonify(data)


@app.route("/api/iocs/<entry_id>")
def iocs(entry_id):
    conn = sqlite3.connect(collector.db_name)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT ioc_type, ioc_value FROM iocs WHERE entry_id = ?", (entry_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    data = [{"type": r[0], "value": r[1]} for r in rows]
    return jsonify(data)


# ----------------------
# RUN MONITOR & FLASK
# ----------------------
conn = sqlite3.connect("CTI2_Feeds.db")
cursor = conn.cursor()
cursor.execute("DELETE FROM cves")  # wipe old enriched data
conn.commit()
conn.close()
print("Cleared cves table — ready for fresh enrichment")


# Chosen Sources
if __name__ == "__main__":
    feeds = [
        ("https://www.cisa.gov/cybersecurity-advisories/all.xml", "CISA ICS"),
        (
            "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
            "CISA ICS",
        ),
        ("https://industrialcyber.co/feed/", "Industrial Cyber"),
        ("https://security.nozominetworks.com/rss.xml", "Nozomi Networks"),
    ]

    # Run a single feed check at startup
    print("Running single check...")
    for url, name in feeds:
        collector.check_feed(url, name)

    collector.recent_entries(limit=30)

    # Show database statistics
    collector.get_stats()

    print("\nStarting CVE enrichment (this may take a while)...")
    NVD_API_KEY = "YOUR_API_KEY_HERE"
    collector.enrich_all_cves(NVD_API_KEY)

    # Start Flask app
    app.run(debug=True)
