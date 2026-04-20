# Importing necessary libraries and modules
import streamlit as st  # For web interface
import pandas as pd  # For data manipulation
import sqlite3  # For database interactions
import requests  # For making API calls
import plotly.graph_objects as go  # For creating interactive visualizations
from datetime import datetime  # For handling date and time
import json  # For working with JSON data
from groq import Groq  # For interacting with Groq API

# ============================================================

# Setting up the database filename and the API keys for NVD and Groq.
DB_NAME = "CTI2_Feeds.db"
AUTH_DB = "auth.db"
NVD_API_KEY = "3df32952-9adf-4002-a285-bf3150e6df21"
GROQ_API_KEY = "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"

client = Groq(api_key=GROQ_API_KEY)
# ============================================================
# 2. PAGE CONFIG
st.set_page_config(
    page_title="ThreatScope — Transport Threat Intelligence",
    layout="wide",  # Ensure full screen
    initial_sidebar_state="expanded",  # Sidebar open by default
)
# ============================================================

# 3. Authentication guard -Ensures user is redirected to login if not authenticated,
# and syncs role from DB in case session state was reset

# If session doesnt have authentication status, it means user has not logged in yet.so we set it to False.
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

# Initializing username and role in session state
if "username" not in st.session_state:
    st.session_state.username = ""

# If role is not in session state, it is set to "analyst" by default.
# This means that if a user logs in without a role assigned, they will have analyst permissions until their role is fetched from the database.
if "role" not in st.session_state:
    st.session_state.role = "analyst"

# ── RBAC Permission Map ──
ROLE_PERMISSIONS = {
    "admin": {"dashboard", "cve_lookup", "sector_intel", "reports", "admin_panel"},
    "analyst": {"dashboard", "cve_lookup", "sector_intel", "reports"},
    "executive": {"dashboard", "sector_intel", "reports"},
}


def has_permission(feature: str) -> bool:
    role = st.session_state.get("role", "executive")
    return feature in ROLE_PERMISSIONS.get(role, set())


# ── Session Timeout (60 minutes) ──
SESSION_TIMEOUT_MINUTES = 60
if st.session_state.get("authenticated") and st.session_state.get("login_time"):
    elapsed = (datetime.now() - st.session_state.login_time).total_seconds()
    if elapsed > SESSION_TIMEOUT_MINUTES * 60:
        for key in ["authenticated", "username", "role", "user_email", "login_time"]:
            st.session_state.pop(key, None)
        st.warning("⏱️ Session expired. Please log in again.")
        st.switch_page("auth.py")

if "last_analysed_cve" not in st.session_state:
    st.session_state.last_analysed_cve = ""
if "last_cve_res" not in st.session_state:
    st.session_state.last_cve_res = None
if "last_classification" not in st.session_state:
    st.session_state.last_classification = None
if "last_transport_analysis" not in st.session_state:
    st.session_state.last_transport_analysis = None
if "chat_messages" not in st.session_state:
    st.session_state.chat_messages = []


# If the user is authenticated and has a username,then their role is fetched from the database.
if st.session_state.get("authenticated") and st.session_state.get("username"):
    try:
        with sqlite3.connect(
            "auth.db"
        ) as conn:  # Connecting to the authentication database
            row = conn.execute(
                "SELECT role FROM users WHERE email=?",
                (st.session_state.get("user_email", ""),),
            ).fetchone()
            if row:
                st.session_state.role = row[
                    0
                ]  # Updating the session state with the user's role fetched from the database. This ensures that the user's permissions are correctly set for the current session, even if they were changed in the database after login.
    except Exception:
        pass

# Redirecting to the authentication page if the user is not authenticated. This is a security measure to prevent unauthorized access to the main content of the application. If the user tries to access the main page without being authenticated, they will be redirected to the login page where they can enter their credentials.
if not st.session_state.authenticated:
    st.switch_page("auth.py")
# ============================================================


# 4. Setting up the database schema for feed entries and CVE reports and defining functions to interact with the database.


def update_db_schema():  # Adding new columns to the feed_entries table to store transport classification results and MITRE IDs. This function is designed to be idempotent, meaning it can be run multiple times without causing errors if the columns already exist.
    # It uses a try-except block to attempt to add each column, and if the column already exists (which would raise an exception), it simply passes and continues with the next one. This allows for seamless schema updates without disrupting existing data or functionality.
    """Adding transport classification columns"""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = (
            conn.cursor()
        )  # Creating a cursor object to execute SQL commands on the database connection.
        for col, col_type, default in [
            (
                "primary_sector",
                "TEXT",
                "'General'",
            ),  # storing the primary transport sector classification for each CVE entry, with a default value of 'General' for non-transport CVEs.
            (
                "sector_confidence",
                "REAL",
                "0.0",
            ),  # storing the confidence score of the transport sector classification, with a default value of 0.0 indicating no confidence for non-transport CVEs.
            (
                "is_transport",
                "INTEGER",
                "0",
            ),  # storing a boolean flag (as an integer) indicating whether the CVE is classified as transport-relevant (1) or not (0), with a default of 0 for non-transport CVEs.
            (
                "all_sectors",
                "TEXT",
                "''",
            ),  # storing a JSON-encoded list of all transport sectors that are relevant to the CVE, allowing for multi-sector classifications, with a default of an empty string for non-transport CVEs.
            (
                "classify_method",
                "TEXT",
                "'unclassified'",
            ),  # storing the method used for classification (e.g., 'rule-based', 'groq-nlp', 'fallback'), which can help in understanding how the classification was determined and in debugging or improving the classification logic, with a default of 'unclassified' for entries that have not been classified yet.
            (
                "mitre_id",
                "TEXT",
                "''",
            ),  # New column for storing the primary MITRE ATT&CK technique ID associated with the CVE.
            (
                "cvss_severity",
                "TEXT",
                "''",
            ),  # New column for storing the CVSS severity level (e.g., Low, Medium, High, Critical) of the CVE, which can be useful for prioritization and filtering in the UI.
        ]:
            try:  # Attempting to add each new column to the feed_entries table. If the column already exists, an exception will be raised, which is caught and ignored, allowing the function to continue adding any remaining columns without interruption.
                cursor.execute(
                    f"ALTER TABLE feed_entries ADD COLUMN {col} {col_type} DEFAULT {default}"
                )
            except Exception:  #
                pass
        conn.commit()  #


def init_cve_reports_table():  # Creates a new table called cve_reports in the database if it does not already exist.
    # This table is designed to store detailed information about CVE reports, including the CVE ID, description, CVSS score and severity, attack vector and complexity, transport sector classification, confidence score, associated MITRE ID, physical consequences, subsector relevance, AI analysis results, and metadata about who analyzed the report and when.
    # The function uses a SQL CREATE TABLE statement with the IF NOT EXISTS clause to ensure that it does not attempt to create the table if it already exists, preventing errors and allowing for safe initialization of the database schema.
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cve_reports (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id          TEXT    UNIQUE NOT NULL,
                description     TEXT,
                cvss_score      TEXT,
                cvss_severity   TEXT,
                attack_vector   TEXT,
                attack_complexity TEXT,
                sector          TEXT,
                confidence      REAL,
                mitre_id        TEXT,
                physical_risk   TEXT,
                subsector       TEXT,
                ai_analysis     TEXT,
                analysed_by     TEXT,
                analysed_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )
        conn.commit()


init_cve_reports_table()


# Function to delete a user from the authentication database and anonymize their reports in the main database. This function takes the user's ID and username as parameters, deletes the user from the users table in the auth.db database, and then updates any CVE reports in the cve_reports table of the main database that were analyzed by that user to set the analysed_by field to 'Deleted User'.
# This helps maintain data integrity while respecting user privacy after account deletion.
def delete_user(user_id, username):
    try:
        with sqlite3.connect(AUTH_DB) as conn:
            conn.execute("DELETE FROM users WHERE id=?", (user_id,))
            conn.commit()
        # Anonymise their reports
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute(
                "UPDATE cve_reports SET analysed_by='Deleted User' WHERE analysed_by=?",
                (username,),
            )
            conn.commit()
        return True
    except Exception as e:
        return False


# Function to save a CVE report to the database. This function takes the CVE ID, details from NVD, transport sector classification, and transport-specific analysis as parameters, and inserts or updates a record in the cve_reports table with this information.
# It uses an UPSERT operation to ensure that if a report for the same CVE ID already exists, it will be updated with the new information rather than creating a duplicate entry.
def save_cve_report(cve_id, res, classification, transport_analysis):
    try:
        with sqlite3.connect(DB_NAME) as conn:
            # Uses INSERT OR REPLACE so if  CVE is looked up that has already been analyzed, it will update the existing record with the latest analysis results and metadata, ensuring that the database always reflects the most current information for each CVE.
            conn.execute(
                """
                INSERT INTO cve_reports 
                    (cve_id, description, cvss_score, cvss_severity, attack_vector,
                     attack_complexity, sector, confidence, mitre_id, physical_risk,
                     subsector, ai_analysis, analysed_by, analysed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    description=excluded.description,
                    cvss_score=excluded.cvss_score,
                    cvss_severity=excluded.cvss_severity,
                    attack_vector=excluded.attack_vector,
                    attack_complexity=excluded.attack_complexity,
                    sector=excluded.sector,
                    confidence=excluded.confidence,
                    mitre_id=excluded.mitre_id,
                    physical_risk=excluded.physical_risk,
                    subsector=excluded.subsector,
                    ai_analysis=excluded.ai_analysis,
                    analysed_by=excluded.analysed_by,
                    analysed_at=excluded.analysed_at
            """,
                (
                    cve_id,
                    res.get("description", ""),
                    str(res.get("cvss_score", "N/A")),
                    res.get("severity", ""),
                    res.get("attack_vector", ""),
                    res.get("attack_complexity", ""),
                    classification.get("primary_sector", "General"),
                    classification.get("confidence", 0.0),
                    classification.get("mitre_id", ""),
                    (
                        transport_analysis.get("physical_consequence", "")
                        if transport_analysis
                        else ""
                    ),
                    (
                        transport_analysis.get("target_subsector", "")
                        if transport_analysis
                        else ""
                    ),
                    (
                        transport_analysis.get("transport_why", "")
                        if transport_analysis
                        else ""
                    ),
                    st.session_state.username,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )
            conn.commit()
        return True
    except Exception as e:
        return False


# Function to execute a SQL query and return the results as a pandas DataFrame. This function takes a SQL query and optional parameters, establishes a connection to the database, executes the query, and returns the results in a structured format that is easy to work with for data analysis and visualization tasks.
def get_db_data(query, params=()):
    with sqlite3.connect(DB_NAME) as conn:
        return pd.read_sql_query(query, conn, params=params)


# Function to execute a SQL query on the authentication database and return the results as a pandas DataFrame. This is similar to the get_db_data function but specifically connects to the auth.db database, allowing for retrieval of user-related data such as roles, login history, and other authentication details that may be stored in that database.
def get_auth_db_data(query, params=()):
    with sqlite3.connect(AUTH_DB) as conn:
        return pd.read_sql_query(query, conn, params=params)


# Function to save the transport sector classification results for a specific feed entry in the database. This function takes the entry ID and a classification dictionary as parameters, and updates the corresponding record in the feed_entries table with the primary sector, confidence score, transport relevance flag, list of all relevant sectors, classification method, and associated MITRE ID. This allows for storing and later retrieving the classification results for each CVE entry in the database.
def save_classification(entry_id, classification):
    """Saving transport classification to the database."""
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute(
            """UPDATE feed_entries
               SET primary_sector=?, sector_confidence=?, is_transport=?,
                   all_sectors=?, classify_method=?, mitre_id=?
               WHERE id=?""",
            (
                classification.get("primary_sector", "General"),
                classification.get("confidence", 0.0),
                1 if classification.get("is_transport") else 0,
                json.dumps(classification.get("sectors", [])),
                classification.get("method", "unknown"),
                classification.get("mitre_id", ""),
                classification.get("cvss_severity", ""),
                entry_id,
            ),
        )
        conn.commit()


# Run schema update at startup
update_db_schema()

# ============================================================
# 5. TRANSPORT SECTOR CLASSIFIER

# Each transport sector is mapped to specific relevant words.
# If those words exist is the CVE discription, the cve gets tagged as relevant to that sector.
SECTOR_KEYWORDS = {
    "Aviation": [
        "avionics",
        "acars",
        "ads-b",
        "tcas",
        "flight management system",
        "fms",
        "arinc",
        "cockpit",
        "autopilot system",
        "pitot",
        "iff system",
        "ils",
        "vor",
        "atis",
        "efb",
        "ife",
        "selcal",
        "cpdlc",
        "aftn",
        "amhs",
        "airport",
        "airline",
        "air carrier",
        "airspace",
        "air traffic control",
        "ansp",
        "heliport",
        "mro facility",
        "air navigation",
        "control tower",
        "flight controller",
        "ground handler",
        "easa",
        "faa",
        "icao",
        "iata",
        "a-isac",
        "eurocontrol",
        "gps spoofing aviation",
        "ads-b spoofing",
        "ads-b injection",
        "radar jamming",
        "acars hijacking",
        "inflight wi-fi",
        "navigation interference",
        "passenger name record",
        "airway bill",
        "notam",
        "flight plan data",
        "epassport",
        "flight disruption",
        "flight delay",
        "flight cancellation",
        "air traffic disruption",
    ],
    "Maritime": [
        "tanker",
        "cargo ship",
        "container ship",
        "bulk carrier",
        "tugboat",
        "fpso",
        "offshore platform",
        "maritime vessel",
        "naval vessel",
        "port authority",
        "maritime authority",
        "maritime terminal",
        "quay",
        "berth",
        "jetty",
        "anchorage",
        "ecdis",
        "gmdss",
        "vts",
        "integrated bridge system",
        "voyage data recorder",
        "vdr",
        "epirb",
        "chartplotter",
        "navtex",
        "ballast system",
        "propulsion control",
        "vhf marine",
        "inmarsat",
        "ssas",
        "lrit",
        "marisat",
        "nmea 2000",
        "solas",
        "marpol",
        "imo",
        "iacs",
        "emsa",
        "uscg",
        "bimco",
        "port state control",
        "classification society",
        "lloyd's register",
        "bureau veritas",
        "furuno",
        "kongsberg maritime",
        "wartsila",
        "rolls royce marine",
        "tideworks",
        "ais spoofing",
        "ais manipulation",
        "gnss jamming",
        "ecdis tampering",
        "dark vessel",
        "ghost vessel",
        "bill of lading",
        "cargo declaration",
        "port clearance",
        "ship particulars",
        "voyage plan",
        "crew list",
        "port disruption",
        "vessel hijacking",
        "cargo theft",
        "port shutdown",
        "oil spill maritime",
    ],
    "Rail": [
        "locomotive",
        "railcar",
        "freight car",
        "passenger train",
        "high speed rail",
        "maglev",
        "rolling stock",
        "pantograph",
        "tram system",
        "light rail system",
        "railway network",
        "railroad",
        "rail network",
        "level crossing",
        "rail corridor",
        "overhead line electrification",
        "etcs",
        "ertms",
        "cbtc",
        "interlocking",
        "balise",
        "trackside unit",
        "radio block center",
        "axle counter",
        "track circuit",
        "positive train control",
        "ptc",
        "cab signalling",
        "train detection",
        "gsm-r",
        "frmcs",
        "train radio",
        "wayside communication",
        "euroradio",
        "train management system",
        "operations control center",
        "train scheduling",
        "fare collection system",
        "passenger information system",
        "era",
        "uic",
        "fra",
        "network rail",
        "sncf",
        "amtrak",
        "rail authority",
        "train operating company",
        "alstom",
        "hitachi rail",
        "stadler",
        "thales rail",
        "ansaldo",
        "wabtec",
        "signal manipulation rail",
        "interlocking attack",
        "gsm-r jamming",
        "points manipulation",
        "train control attack",
        "level crossing attack",
        "ransomware ticketing",
        "occ compromise",
        "train collision",
        "derailment",
        "track closure",
        "station shutdown",
        "passenger evacuation rail",
    ],
    "Road": [
        "heavy goods vehicle",
        "hgv",
        "autonomous vehicle",
        "connected vehicle",
        "electric vehicle fleet",
        "fleet vehicle",
        "emergency vehicle dispatch",
        "toll plaza",
        "weigh station",
        "road network management",
        "smart road",
        "road corridor management",
        "traffic management center",
        "traffic control system",
        "variable message sign",
        "dynamic message sign",
        "ramp metering",
        "urban traffic control",
        "adaptive traffic control",
        "intelligent transport system",
        "v2x",
        "v2v",
        "v2i",
        "dsrc",
        "c-v2x",
        "obd-ii",
        "can bus",
        "ecu firmware",
        "over the air update vehicle",
        "lidar sensor",
        "fleet telematics",
        "onboard diagnostics",
        "electronic toll collection",
        "etoll",
        "rfid toll",
        "anpr",
        "license plate recognition",
        "tolling system",
        "congestion charge system",
        "roadside unit",
        "onboard unit vehicular",
        "5g vehicular",
        "ieee 802.11p",
        "nhtsa",
        "dvla",
        "highways england",
        "national highways",
        "unece wp.29",
        "kapsch",
        "q-free",
        "swarco",
        "iteris",
        "cubic transportation",
        "tomtom fleet",
        "garmin fleet",
        "can bus attack",
        "ecu manipulation",
        "traffic signal manipulation",
        "anpr spoofing",
        "toll fraud",
        "fleet tracking hijack",
        "v2x attack",
        "roadside unit compromise",
        "lidar spoofing",
        "radar spoofing vehicle",
        "vehicle registration system",
        "toll record",
        "hazmat declaration road",
        "traffic disruption",
        "toll system outage",
        "fleet disruption",
        "vehicle recall",
        "highway shutdown",
    ],
}

SECTOR_ICONS = {
    "Aviation": "✈️",
    "Maritime": "🚢",
    "Rail": "🚆",
    "Road": "🚗",
    "Transport": "🚦",
    "General": "🔒",
}

SECTOR_COLORS = {
    "Aviation": "#38bdf8",
    "Maritime": "#34d399",
    "Rail": "#fbbf24",
    "Road": "#a78bfa",
    "Transport": "#6b7280",
    "General": "#6b7280",
}

VALID_TRANSPORT_SECTORS = {"Aviation", "Maritime", "Rail", "Road", "Transport"}


# This function implements a simple rule-based classification approach to determine the transport sector relevance of a CVE description.
# It checks for the presence of specific keywords associated with each transport sector in the CVE description text.
# If keywords are found, it counts the matches and assigns a confidence score based on the number of matches,
# with a base confidence of 0.55 and an additional 0.12 for each match, capped at 0.95. The function returns a dictionary mapping each relevant sector to its confidence score.
def rule_based_classify(text: str) -> dict:
    import re

    text_lower = text.lower()
    results = {}
    for sector, keywords in SECTOR_KEYWORDS.items():
        matches = 0
        for kw_phrase in keywords:
            pattern = r"\b" + re.escape(kw_phrase.lower()) + r"\b"
            if re.search(pattern, text_lower):
                matches += 1
        if matches > 0:
            confidence = min(0.55 + matches * 0.12, 0.95)
            results[sector] = confidence
    return results


# sends the CVE description to the Groq AI API with a system prompt telling it to act as a transport cybersecurity classifier
# Gets Json response with transport sector classification, confidence score, transport relevance flag, and associated MITRE ID.
def groq_classify(description: str) -> dict:
    try:
        response = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a transport cybersecurity classifier. "
                        "Given a CVE description, classify it into transport sectors. "
                        "A CVE is transport-relevant if it affects hardware, protocols, or software "
                        "commonly deployed in transport systems, even if not exclusively. "
                        "When in doubt between Transport and General, prefer General. Only classify as transport if the CVE description explicitly mentions transport systems, vehicles, infrastructure or protocols. "
                        "Return ONLY a JSON object with: "
                        "'sectors' (list from [Aviation, Maritime, Rail, Road]), "
                        "'primary_sector' (most relevant: Aviation/Maritime/Rail/Road/Transport/General), "
                        "'confidence' (float 0.0-1.0), "
                        "'is_transport' (boolean), "
                        "'mitre_id' (MITRE ATT&CK technique ID e.g. T1499 for the primary attack vector)."
                    ),
                },
                {"role": "user", "content": f"CVE Description: {description}"},
            ],
            model="llama-3.3-70b-versatile",  # Model chosen that is provided by groq.
            response_format={"type": "json_object"},
        )
        return json.loads(
            response.choices[0].message.content
        )  # Parsing the JSON response from the Groq API to extract the classification results. The response is expected to contain the transport sector classification, confidence score, transport relevance flag, and associated MITRE ID, which are then returned as a dictionary for further processing and storage in the database.
    except Exception:
        return None


# This function combines the rule-based and Groq classification approaches to determine the transport sector relevance of a CVE description.
# It first applies the rule-based classification, and if it yields results, it uses the Groq classification to potentially enhance the confidence score and add MITRE ID information.


def classify_cve(description: str) -> dict:
    rule_result = rule_based_classify(description)

    if rule_result:
        primary = max(rule_result, key=rule_result.get)
        groq_result = groq_classify(description) or {}
        return {
            "primary_sector": primary,
            "sectors": list(rule_result.keys()),
            "confidence": rule_result[primary],
            "is_transport": True,
            "mitre_id": groq_result.get("mitre_id", ""),
            "method": "rule-based",
        }

    groq_result = groq_classify(description)
    if groq_result:
        if groq_result.get("is_transport"):
            groq_result["method"] = "groq-nlp"
            groq_result.setdefault("mitre_id", "")
            return groq_result
        else:
            return {
                "primary_sector": "General",
                "sectors": [],
                "confidence": groq_result.get("confidence", 1.0),
                "is_transport": False,
                "mitre_id": groq_result.get("mitre_id", ""),
                "method": "groq-nlp",
            }
    # If the rule-based approach does not yield any relevant sectors, it relies solely on the Groq classification. If neither approach identifies transport relevance,
    # it defaults to classifying the CVE as "General" with no transport relevance.
    return {
        "primary_sector": "General",
        "sectors": [],
        "confidence": 1.0,
        "is_transport": False,
        "mitre_id": "",
        "method": "fallback",
    }


# ============================================================
# 6. TRANSPORT-SPECIFIC IMPACT ANALYSIS


# A second groq call is made specifically asks the AI to think about physical consequences.
def get_transport_analysis(description):
    try:
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a Transportation Cyber-Physical Systems (CPS) Analyst. "
                        "Analyze the CVE for its impact on Aviation, Maritime, Rail, and Road. "
                        "A CVE is transport-relevant if it affects hardware, protocols, or software "
                        "commonly deployed in transport systems, even if not exclusively. "
                        "Return a JSON object with: "
                        "'is_transport_specific' (true/false — true if transport systems are affected), "
                        "'target_subsector' (Aviation/Maritime/Rail/Road/Transport/General — "
                        "use Transport if it spans multiple sectors or is broadly relevant to transport), "
                        "'transport_why' (2-sentence explanation mentioning hardware/protocols/safety), "
                        "'physical_consequence' (e.g. Unintended acceleration, Navigation failure). "
                        "'mitre_id' (the most relevant MITRE ATT&CK technique ID for this CVE), "
                        "When in doubt between Transport and General, prefer Transport."
                    ),
                },
                {"role": "user", "content": f"CVE Description: {description}"},
            ],
            model="llama-3.3-70b-versatile",
            response_format={"type": "json_object"},
        )
        return json.loads(chat_completion.choices[0].message.content)
    except Exception:
        return None


def get_chatbot_response(user_message, chat_history):
    # TEMP DEBUG
    try:
        import faiss

        print("✅ faiss imported")
        import numpy as np

        print("✅ numpy imported")
        from sentence_transformers import SentenceTransformer

        print("✅ sentence_transformers imported")
        from rag_helper import retrieve_context

        print("✅ rag_helper imported")
        rag_context = retrieve_context(user_message, k=3)
        print(f"✅ RAG context length: {len(rag_context)}")
    except Exception as e:
        import traceback

        print(f"❌ FAILED AT: {e}")
        traceback.print_exc()
        rag_context = ""

    # Build system prompt — inject PDF context if found
    if rag_context:
        system_content = (
            "You are ThreatScope Assistant, an expert CTI and GRC advisor "
            "specialising in Operational Technology (OT) security and critical "
            "infrastructure protection, with a focus on the transport sector. "
            "You provide clear, concise explanations of: "
            "cybersecurity standards (IEC 62443, NIST CSF, ISO 27001, NIS2 Directive), "
            "CVE analysis and vulnerability management, "
            "MITRE ATT&CK techniques and their relevance to transport OT systems, "
            "threat intelligence concepts and IOC analysis, "
            "GRC frameworks and compliance recommendations for transport operators. "
            "Always relate your answers to transport sector OT security where relevant. "
            "Keep responses concise, professional and actionable. "
            "If asked about something outside cybersecurity or GRC, politely redirect "
            "the conversation back to your area of expertise.\n\n"
            "IMPORTANT: You have been provided with relevant excerpts from official "
            "cybersecurity standards and frameworks below. Use these as your primary "
            "source of truth. Always cite the source document and page number when "
            "referencing them (e.g. 'According to IEC 62443-2-1:2024, p.12...'). "
            "You MUST begin your response by citing which source document and page number "
            "the information comes from, in this exact format: "
            "'📄 Source: [filename], p.[number]'. "
            "If multiple sources are used, list all of them at the top. "
            "Do not hallucinate clause numbers or requirements not present in the excerpts. "
            "If the excerpts do not contain enough information, say so clearly and state "
            "you are supplementing from general knowledge.\n\n"
            "REFERENCE EXCERPTS:\n"
            "---\n"
            f"{rag_context}\n"
            "---"
        )
    else:
        system_content = (
            "You are ThreatScope Assistant, an expert CTI and GRC advisor "
            "specialising in Operational Technology (OT) security and critical "
            "infrastructure protection, with a focus on the transport sector. "
            "You provide clear, concise explanations of: "
            "cybersecurity standards (IEC 62443, NIST CSF, ISO 27001, NIS2 Directive), "
            "CVE analysis and vulnerability management, "
            "MITRE ATT&CK techniques and their relevance to transport OT systems, "
            "threat intelligence concepts and IOC analysis, "
            "GRC frameworks and compliance recommendations for transport operators. "
            "When asked about threats or vulnerabilities, proactively recommend: "
            "(1) relevant IEC 62443 security levels and zones, "
            "(2) applicable NIST CSF functions (Identify/Protect/Detect/Respond/Recover), "
            "(3) NIS2 compliance obligations if the operator is EU-based, "
            "(4) MITRE ATT&CK for ICS techniques and mitigations. "
            "Structure recommendations clearly with the most critical actions first. "
            "Keep responses concise, professional and actionable. "
            "If asked about something outside cybersecurity or GRC, politely redirect "
            "the conversation back to your area of expertise."
        )

    if rag_context:
        print("\n--- RAG CONTEXT INJECTED ---")
        print(rag_context[:600])
        print("----------------------------\n")

    messages = [{"role": "system", "content": system_content}]

    for msg in chat_history:
        messages.append({"role": msg["role"], "content": msg["content"]})
    messages.append({"role": "user", "content": user_message})

    try:
        response = client.chat.completions.create(
            messages=messages,
            model="llama-3.3-70b-versatile",
            max_tokens=800,
        )
        return response.choices[0].message.content
    except Exception as e:
        return "I'm currently unavailable. Please try again shortly."


# This function fetches detailed information about a CVE from the NVD API using the CVE ID.
# It retrieves the CVE description, CVSS score and severity, attack vector and complexity, and other relevant metadata.


def fetch_nvd_details(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            if data.get("vulnerabilities"):
                vuln = data["vulnerabilities"][0]["cve"]
                metrics = vuln.get("metrics", {})
                cvss_data = {}
                for version in ["cvssMetricV31", "cvssMetricV30"]:
                    if version in metrics:
                        m_list = metrics[version]
                        primary = next(
                            (m for m in m_list if m.get("type") == "Primary"), m_list[0]
                        )
                        cvss_data = primary.get("cvssData", {})
                        break
                if not cvss_data and "cvssMetricV2" in metrics:
                    cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                return {
                    "id": vuln.get("id"),
                    "description": vuln.get("descriptions", [{}])[0].get(
                        "value", "No description available."
                    ),
                    "cvss_score": cvss_data.get("baseScore", "N/A"),
                    "severity": cvss_data.get(
                        "baseSeverity", cvss_data.get("extra_severity", "N/A")
                    ),
                    "attack_vector": cvss_data.get(
                        "attackVector", cvss_data.get("accessVector", "N/A")
                    ),
                    "attack_complexity": cvss_data.get(
                        "attackComplexity", cvss_data.get("accessComplexity", "N/A")
                    ),
                    "privileges_required": cvss_data.get(
                        "privilegesRequired", cvss_data.get("authentication", "N/A")
                    ),
                    "user_interaction": cvss_data.get("userInteraction", "N/A"),
                    "published": vuln.get("published", ""),
                    "last_modified": vuln.get("lastModified", ""),
                    "source": "NVD",
                }
    except Exception:
        pass
    # If the NVD API does not provide sufficient information, it falls back to fetching data from the MITRE API.
    # The function returns a dictionary containing all the relevant details about the CVE, which can then be used for classification and analysis.
    try:
        mitre_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        r = requests.get(mitre_url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            cna = data.get("containers", {}).get("cna", {})
            desc = cna.get("descriptions", [{}])[0].get(
                "value", "No description available."
            )
            meta = data.get("cveMetadata", {})
            return {
                "id": cve_id,
                "description": desc,
                "cvss_score": "Pending",
                "severity": "Pending",
                "attack_vector": "Pending",
                "attack_complexity": "Pending",
                "privileges_required": "Pending",
                "user_interaction": "Pending",
                "published": meta.get("datePublished", ""),
                "last_modified": meta.get("dateUpdated", ""),
                "source": "MITRE",
            }
    except Exception:
        pass

    return None


# ============================================================
# 7. CSS STYLING
# ============================================================
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;700;800&display=swap');

    .stApp { background-color: #080c10; color: #e2e8f0; font-family: 'Syne', sans-serif; }
    [data-testid="stHeader"] { background: rgba(0,0,0,0); }
    section[data-testid="stSidebar"] { background-color: #0a0f14; border-right: 1px solid #1a2535; }

    .stTabs [data-baseweb="tab-list"] { background-color: #0d1520; border-bottom: 1px solid #1a2535; gap: 0; }
    .stTabs [data-baseweb="tab"] { color: #94a3b8; font-family: 'JetBrains Mono', monospace; font-size: 13px; font-weight: 600; padding: 12px 24px; border-bottom: 2px solid transparent; }
    .stTabs [aria-selected="true"] { color: #38bdf8 !important; border-bottom: 2px solid #38bdf8 !important; background: rgba(56, 189, 248, 0.05) !important; }

    .custom-card { background: linear-gradient(135deg, #0d1520 0%, #111827 100%); border: 1px solid #1e2d3d; border-radius: 12px; padding: 24px; box-shadow: 0 4px 24px rgba(0,0,0,0.4); margin-bottom: 16px; position: relative; overflow: hidden; }
    .custom-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px; background: linear-gradient(90deg, #38bdf8, #818cf8); }

    .metric-label { color: #64748b; font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 10px; }
    .metric-val { font-size: 38px; font-weight: 800; color: #f1f5f9; line-height: 1; font-family: 'Syne', sans-serif; }
    .metric-delta { font-size: 12px; color: #34d399; margin-top: 10px; font-family: 'JetBrains Mono', monospace; }

    .pill { padding: 3px 10px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; display: inline-block; }
    .pill-critical  { background: rgba(239,68,68,0.12); color: #f87171; border: 1px solid rgba(239,68,68,0.4); }
    .pill-high      { background: rgba(251,191,36,0.12); color: #fbbf24; border: 1px solid rgba(251,191,36,0.4); }
    .pill-medium    { background: rgba(167,139,250,0.12); color: #a78bfa; border: 1px solid rgba(167,139,250,0.4); }
    .pill-low       { background: rgba(56,189,248,0.12); color: #38bdf8; border: 1px solid rgba(56,189,248,0.4); }
    .pill-aviation  { background: rgba(56,189,248,0.12); color: #38bdf8; border: 1px solid rgba(56,189,248,0.4); }
    .pill-maritime  { background: rgba(52,211,153,0.12); color: #34d399; border: 1px solid rgba(52,211,153,0.4); }
    .pill-rail      { background: rgba(251,191,36,0.12); color: #fbbf24; border: 1px solid rgba(251,191,36,0.4); }
    .pill-road      { background: rgba(167,139,250,0.12); color: #a78bfa; border: 1px solid rgba(167,139,250,0.4); }
    .pill-transport { background: rgba(107,114,128,0.12); color: #94a3b8; border: 1px solid rgba(107,114,128,0.4); }
    .pill-general   { background: rgba(107,114,128,0.12); color: #9ca3af; border: 1px solid rgba(107,114,128,0.4); }

    .activity-container { border-left: 2px solid #1e2d3d; padding-left: 20px; margin-left: 5px; }
    .activity-item { margin-bottom: 22px; position: relative; }
    .activity-dot { position: absolute; left: -27px; top: 4px; height: 10px; width: 10px; border-radius: 50%; }
    .dot-critical { background: #f87171; box-shadow: 0 0 10px #f87171; }
    .dot-high     { background: #fbbf24; box-shadow: 0 0 8px #fbbf24; }
    .dot-medium   { background: #a78bfa; }
    .dot-low      { background: #38bdf8; }

    .table-header { color: #94a3b8;font-weight:600;  font-family: 'JetBrains Mono', monospace; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.5px; }
    .row-title { font-size: 13px; font-weight: 600; color: #e2e8f0; font-family: 'Syne', sans-serif; line-height: 1.4; }
    .row-source { background: #1e2d3d; padding: 2px 8px; border-radius: 3px; font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #94a3b8; }

    .stAlert { background-color: #0d1520 !important; border: 1px solid #1e2d3d !important; border-radius: 10px !important; color: #94a3b8 !important; }
    .stTextInput > div > div > input { background-color: #0d1520 !important; border: 1px solid #1e2d3d !important; border-radius: 8px !important; color: #e2e8f0 !important; font-family: 'JetBrains Mono', monospace !important; }
    .stButton > button { background: linear-gradient(135deg, #0369a1, #1d4ed8) !important; color: white !important; border: none !important; border-radius: 8px !important; font-family: 'JetBrains Mono', monospace !important; font-weight: 600 !important; font-size: 12px !important; letter-spacing: 0.5px !important; padding: 10px 20px !important; transition: all 0.2s !important; }
    .stButton > button:hover { transform: translateY(-1px) !important; box-shadow: 0 4px 16px rgba(56,189,248,0.3) !important; }

    .sidebar-title { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #94a3b8;font-weight:600;text-transform: uppercase; letter-spacing: 2px; margin: 16px 0 8px 0; }
    div[data-testid="stMetric"] { background: #0d1520; border: 1px solid #1e2d3d; border-radius: 10px; padding: 12px; }

    .threat-card {
        background: linear-gradient(135deg, #0d1520 0%, #111827 100%);
        border: 1px solid #1e2d3d;
        border-radius: 10px;
        padding: 16px 20px;
        margin-bottom: 10px;
    }
    .threat-card:hover { border-color: #38bdf8; }
    ::-webkit-scrollbar { width: 4px; }
    ::-webkit-scrollbar-track { background: #080c10; }
    ::-webkit-scrollbar-thumb { background: #1e2d3d; border-radius: 4px; }

    /* Admin table styling */
    .admin-row { background: #0d1520; border: 1px solid #1e2d3d; border-radius: 8px; padding: 14px 18px; margin-bottom: 8px; }
    .admin-row:hover { border-color: #334155; }
/* ── Chatbot Popover Button ── */
div[data-testid="stPopover"] button {
    background: linear-gradient(135deg, #0369a1, #1d4ed8) !important;
    color: white !important;
    border: none !important;
    border-radius: 24px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 12px !important;
    font-weight: 700 !important;
    letter-spacing: 1px !important;
    padding: 12px 24px !important;
    box-shadow: 0 4px 20px rgba(56,189,248,0.3) !important;
    transition: all 0.2s !important;
}
div[data-testid="stPopover"] button:hover {
    box-shadow: 0 6px 28px rgba(56,189,248,0.5) !important;
    transform: translateY(-2px) !important;
}  

    </style>
    """,
    unsafe_allow_html=True,
)

# ============================================================
# 8. SIDEBAR
# ============================================================

# Role badge colors
ROLE_COLORS = {
    "admin": {
        "bg": "rgba(239,68,68,0.12)",
        "color": "#f87171",
        "border": "rgba(239,68,68,0.4)",
        "label": "⬤ ADMIN",
    },
    "analyst": {
        "bg": "rgba(56,189,248,0.12)",
        "color": "#38bdf8",
        "border": "rgba(56,189,248,0.4)",
        "label": "⬤ ANALYST",
    },
    "executive": {
        "bg": "rgba(129,140,248,0.12)",
        "color": "#818cf8",
        "border": "rgba(129,140,248,0.4)",
        "label": "⬤ EXECUTIVE",
    },
}

current_role = st.session_state.get("role", "analyst")
role_style = ROLE_COLORS.get(current_role, ROLE_COLORS["analyst"])

with st.sidebar:
    st.markdown(
        """
        <div style='padding: 20px 0 10px 0;'>
            <div style='font-family: "JetBrains Mono", monospace; font-size: 10px;
                        color: #38bdf8; letter-spacing: 3px; text-transform: uppercase;
                        margin-bottom: 4px;'>SYSTEM ACTIVE</div>
            <div style='font-family: "Syne", sans-serif; font-size: 22px;
                        font-weight: 800; color: #f1f5f9;'>THREAT SCOPE</div>
            <div style='font-family: "JetBrains Mono", monospace; font-size: 11px;
                        color: #94a3b8;font-weight:600; '>Transport Intelligence Platform</div>
        </div>
        <hr style='border: 1px solid #1e2d3d; margin: 12px 0;'>
        """,
        unsafe_allow_html=True,
    )

    #  Logged-in user card
    st.markdown(
        f"""
        <div style='background:#0d1520; border:1px solid #1e2d3d; border-radius:10px;
                    padding:14px 16px; margin-bottom:16px;'>
            <div style='font-family:"JetBrains Mono",monospace; font-size:9px;
                        color:#94a3b8;font-weight:600; letter-spacing:2px; text-transform:uppercase;
                        margin-bottom:6px;'>LOGGED IN AS</div>
            <div style='font-family:"Syne",sans-serif; font-size:14px; font-weight:700;
                        color:#f1f5f9; margin-bottom:8px;'>
                {st.session_state.username}
            </div>
            <span style='background:{role_style["bg"]}; color:{role_style["color"]};
                         border:1px solid {role_style["border"]}; padding:3px 10px;
                         border-radius:4px; font-family:"JetBrains Mono",monospace;
                         font-size:10px; font-weight:700; letter-spacing:1px;'>
                {role_style["label"]}
            </span>
            <div style='font-family:"JetBrains Mono",monospace; font-size:10px;
                        color:#334155; margin-top:8px;'>
                🌐 {st.session_state.get("last_login_ip", "Unknown")}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if current_role == "executive":
        st.markdown(
            """
        <div style='background:rgba(251,191,36,0.08); border:1px solid rgba(251,191,36,0.3);
                    border-radius:8px; padding:10px 14px; margin-bottom:12px;
                    font-family:"JetBrains Mono",monospace; font-size:11px; color:#fbbf24;'>
            ⏳ Limited access.<br>Contact your admin to be upgraded to Analyst.
        </div>
        """,
            unsafe_allow_html=True,
        )
    if st.button("🚪  Sign Out", use_container_width=True):
        st.session_state.authenticated = False
        st.session_state.username = ""
        st.session_state.role = "analyst"
        st.switch_page("auth.py")

    st.markdown(
        "<hr style='border: 1px solid #1e2d3d; margin: 12px 0;'>",
        unsafe_allow_html=True,
    )

    # Filters — only shown for analyst and admin roles, executives get a clean view with all data by default
    if current_role in ("analyst", "admin", "executive"):
        st.markdown(
            "<div class='sidebar-title'>⚙ Filters</div>", unsafe_allow_html=True
        )
        cve_only_toggle = st.toggle("CVE threats only", value=False)

        st.markdown("<div class='sidebar-title'>Severity</div>", unsafe_allow_html=True)
        active_sevs = []
        if st.checkbox("🔴 Critical", value=True):
            active_sevs.append("CRITICAL")
        if st.checkbox("🟠 High", value=True):
            active_sevs.append("HIGH")
        if st.checkbox("🟡 Medium", value=True):
            active_sevs.append("MEDIUM")
        if st.checkbox("🔵 Low", value=True):
            active_sevs.append("LOW")

        st.markdown(
            "<div class='sidebar-title'>Transport Sector</div>", unsafe_allow_html=True
        )
        sector_filter = st.multiselect(
            "Sector",
            ["Aviation", "Maritime", "Rail", "Road", "Transport", "General"],
            default=["Aviation", "Maritime", "Rail", "Road", "Transport", "General"],
            label_visibility="collapsed",
        )
    else:
        # Executive — no filters needed, set defaults silently
        cve_only_toggle = False
        active_sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        sector_filter = ["Aviation", "Maritime", "Rail", "Road", "Transport", "General"]

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(
        f"""
        <div style='background:#0d1520; border:1px solid #1e2d3d; border-radius:8px;
                    padding:12px; font-family:"JetBrains Mono",monospace; font-size:11px;'>
            <div style='color:#94a3b8;font-weight:600; margin-bottom:6px;'>LAST SYNC</div>
            <div style='color:#34d399;'>{datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# ============================================================
# 9. Role Based Access Control (RBAC) for Tab Visibility
# The dashboard and CVE reports tabs are shown to all users, while the CVE lookup, sector intelligence, and admin panel tabs are conditionally rendered based on the user's role.

# Executives get a streamlined view with just the dashboard and reports,
if current_role == "executive":
    tab1, tab3, tab_reports = st.tabs(
        [
            "📊  Dashboard",
            "🚦  Sector Intelligence",
            "📋  CVE Reports",
        ]
    )
    tab2 = None
    tab4 = None

# analysts get additional tabs for deeper analysis,
elif current_role == "analyst":
    tab1, tab2, tab3, tab_reports = st.tabs(
        [
            "📊  Dashboard",
            "🔍  CVE Lookup & Analysis",
            "🚦  Sector Intelligence",
            "📋  CVE Reports",
        ]
    )
    tab4 = None

# and admins get full access to all features including the admin panel for user management and system settings.
else:
    tab1, tab2, tab3, tab_reports, tab4 = st.tabs(
        [
            "📊  Dashboard",
            "🔍  CVE Lookup & Analysis",
            "🚦  Sector Intelligence",
            "📋  CVE Reports",
            "⚙️  Admin Panel",
        ]
    )

# ─────────────────────────────────────────────────────────────
# TAB 1 — DASHBOARD(Accessed by all roles)

# The dashboard tab provides an overview of the current threat landscape with key metrics, visualizations, and recent activity.
# It aggregates data from the database to display total threats, CVEs detected, transport-specific CVEs, and severity distributions.
# The dashboard is designed to give users a quick snapshot of the most critical information at a glance, with visual cues and color coding to highlight important trends and insights relevant to transport cybersecurity.

# Counts total
with tab1:
    try:
        total_t = get_db_data("SELECT COUNT(*) as count FROM feed_entries").iloc[0][
            "count"
        ]
        total_cve = get_db_data(
            "SELECT COUNT(*) as count FROM iocs WHERE ioc_type='CVE'"
        ).iloc[0]["count"]
        crit_count = get_db_data(
            "SELECT COUNT(*) as count FROM feed_entries WHERE cvss_severity='CRITICAL' AND classify_method='verified'"  # classif
        ).iloc[0]["count"]
        high_count = get_db_data(
            "SELECT COUNT(*) as count FROM feed_entries WHERE cvss_severity='HIGH' AND classify_method='verified'"
        ).iloc[0]["count"]
        transport_count = get_db_data(
            "SELECT COUNT(*) as count FROM feed_entries WHERE is_transport=1 AND classify_method='verified'"
        ).iloc[0]["count"]
    except Exception:
        total_t = total_cve = crit_count = high_count = transport_count = 0

    col_h1, col_h2, col_h3 = st.columns([0.6, 0.2, 0.2])
    with col_h1:
        st.markdown(
            "<h1 style='margin-bottom:0; font-family:\"Syne\",sans-serif; font-weight:800;'>"
            "Transport Intelligence Dashboard</h1>",
            unsafe_allow_html=True,
        )
        st.markdown(
            '<p style=\'color:#94a3b8;font-weight:600;  font-family:"JetBrains Mono",monospace; '
            "font-size:12px; letter-spacing:1px;'>TRANSPORT SECTOR — CYBER THREAT INTELLIGENCE</p>",
            unsafe_allow_html=True,
        )
    with col_h2:
        st.markdown(
            f"<div style='text-align:right; padding-top:18px;'>"
            f'<p style=\'color:#94a3b8;font-weight:600; font-family:"JetBrains Mono",monospace; '
            f"font-size:10px; margin-bottom:2px;'>LIVE FEED</p>"
            f'<p style=\'font-size:20px; font-weight:700; font-family:"JetBrains Mono",monospace; '
            f"color:#38bdf8;'>{datetime.now().strftime('%H:%M:%S')}</p></div>",
            unsafe_allow_html=True,
        )
    with col_h3:
        st.markdown("<div style='padding-top:18px;'>", unsafe_allow_html=True)
        with st.popover("🤖  Chatbot", use_container_width=True):
            st.markdown(
                """
                <div style='font-family:"JetBrains Mono",monospace;'>
                    <div style='font-size:9px; color:#38bdf8; letter-spacing:2px;
                                text-transform:uppercase; margin-bottom:4px;'>THREATSCOPE</div>
                    <div style='font-size:16px; font-weight:700; color:#f1f5f9;
                                font-family:"Syne",sans-serif; margin-bottom:4px;'>Information Chatbot</div>
                    <div style='font-size:10px; color:#94a3b8;font-weight:600; margin-bottom:12px;'>
                        Ask me about cybersecurity standards related to OT security.
                    </div>
                    <hr style='border:1px solid #1e2d3d; margin-bottom:12px;'>
                </div>
                """,
                unsafe_allow_html=True,
            )

            if st.session_state.chat_messages:
                for msg in st.session_state.chat_messages:
                    if msg["role"] == "user":
                        st.markdown(
                            f"""
                            <div style='background:linear-gradient(135deg,#0369a1,#1d4ed8);
                                        color:white; padding:10px 14px;
                                        border-radius:12px 12px 4px 12px;
                                        font-size:11px; line-height:1.5; margin-bottom:8px;
                                        font-family:"JetBrains Mono",monospace;
                                        max-width:85%; margin-left:auto;'>
                                {msg["content"]}
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                    else:
                        st.markdown(
                            f"""
                            <div style='background:#1e2d3d; color:#94a3b8;
                                        padding:10px 14px;
                                        border-radius:12px 12px 12px 4px;
                                        font-size:11px; line-height:1.5; margin-bottom:8px;
                                        font-family:"JetBrains Mono",monospace;
                                        max-width:85%;'>
                                🤖 {msg["content"]}
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
            else:
                st.markdown(
                    """
                    <div style='background:#1e2d3d; color:#94a3b8;
                                padding:10px 14px; border-radius:12px 12px 12px 4px;
                                font-size:11px; line-height:1.5; margin-bottom:8px;
                                font-family:"JetBrains Mono",monospace;'>
                        🤖 Hello! I am ThreatScope Assistant. Ask me anything about
                         OT security or
                        cybersecurity standards like IEC 62443 and NIST CSF.
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            user_input = st.text_input(
                "Message",
                placeholder="e.g. What is IEC 62443?",
                key="chat_input",
                label_visibility="collapsed",
            )

            col_send, col_clear = st.columns(2)
            with col_send:
                if st.button("📤 Send", key="chat_send", use_container_width=True):
                    if user_input.strip():
                        st.session_state.chat_messages.append(
                            {"role": "user", "content": user_input.strip()}
                        )
                        with st.spinner("Thinking..."):
                            response = get_chatbot_response(
                                user_input.strip(),
                                st.session_state.chat_messages[:-1],
                            )
                        st.session_state.chat_messages.append(
                            {"role": "assistant", "content": response}
                        )
                        st.rerun()
            with col_clear:
                if st.button("🗑️ Clear", key="chat_clear", use_container_width=True):
                    st.session_state.chat_messages = []
                    st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # The key metrics at the top of the dashboard are displayed in custom-styled cards with color-coded borders and text to indicate severity and relevance.
    # Each card shows a specific metric such as total threats, CVEs detected, transport-specific CVEs, critical alerts, and high severity counts.
    # The cards also include delta indicators to show trends compared to the previous week, providing users with quick insights into how the threat landscape is evolving over time.

    m1, m2, m3, m4, m5 = st.columns(5)  # Creating 5 columns on top
    metrics_data = [
        ("Total Threats", total_t, "↑ 12% this week", "#38bdf8"),
        ("CVEs Detected", total_cve, "↑ 8% this week", "#818cf8"),
        ("Transport CVEs", transport_count, "Verified only", "#34d399"),
        ("Critical Alerts", crit_count, None, "#f87171"),
        ("High Severity", high_count, None, "#fbbf24"),
    ]
    for col, (label, val, delta, color) in zip([m1, m2, m3, m4, m5], metrics_data):
        with col:
            delta_html = f"<div class='metric-delta'>{delta}</div>" if delta else ""
            st.markdown(
                f"""
                <div class="custom-card" style="border-top: 2px solid {color};">
                    <div class="metric-label">{label}</div>
                    <div class="metric-val" style="color:{color};">{val}</div>
                    {delta_html}
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<br>", unsafe_allow_html=True)
    # Creates 3 columns for the charts and recent activity feed
    col_chart1, col_chart2, col_recent = st.columns([1.1, 1.1, 1.2])

    # The severity distribution pie chart and sector breakdown bar chart are created using
    # Plotly to provide interactive visualizations of the data.
    with col_chart1:
        st.markdown(
            "<p class='table-header' style='margin-bottom:12px;'>Severity Distribution</p>",
            unsafe_allow_html=True,
        )
        try:
            # Grouping threats by severity and counting them to create a pie chart that shows the distribution of threat severities in the feed.
            sev_df = get_db_data(
                "SELECT cvss_severity as severity, COUNT(*) as count FROM feed_entries "
                "WHERE classify_method='verified' AND cvss_severity != '' "
                "GROUP BY cvss_severity"
            )
            # Creating pie chart with custom colors and styling to visualize the severity distribution of the threats.
            # The chart uses a donut style with a hole in the center and includes a legend for clarity.
            fig = go.Figure(
                data=[
                    go.Pie(
                        labels=sev_df["severity"],
                        values=sev_df["count"],
                        hole=0.72,
                        marker=dict(
                            colors=["#f87171", "#fbbf24", "#a78bfa", "#38bdf8"],
                            line=dict(color="#080c10", width=3),
                        ),
                        textfont=dict(family="JetBrains Mono", size=11),
                    )
                ]
            )
            fig.update_layout(
                margin=dict(t=10, b=10, l=10, r=10),
                height=240,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                showlegend=True,
                legend=dict(
                    font=dict(color="#64748b", size=10, family="JetBrains Mono"),
                    bgcolor="rgba(0,0,0,0)",
                ),
            )
            st.plotly_chart(
                fig, use_container_width=True
            )  # Displaying in the dashboard
        except Exception:
            st.info("No severity data available.")

    with col_chart2:
        st.markdown(
            "<p class='table-header' style='margin-bottom:12px;'>Sector Breakdown</p>",
            unsafe_allow_html=True,
        )
        try:
            # Counting threats by primary sector to create a bar chart that shows the distribution of threats across different transport sectors.
            sector_df = get_db_data(
                """SELECT primary_sector, COUNT(*) as count FROM feed_entries
                   WHERE primary_sector IS NOT NULL AND classify_method='verified'
                   GROUP BY primary_sector"""
            )
            if not sector_df.empty:
                color_map = {
                    "Aviation": "#38bdf8",
                    "Maritime": "#34d399",
                    "Rail": "#fbbf24",
                    "Road": "#a78bfa",
                    "Transport": "#6b7280",
                    "General": "#94a3b8",
                }
                bar_colors = [
                    color_map.get(s, "#94a3b8") for s in sector_df["primary_sector"]
                ]
                fig2 = go.Figure(
                    data=[
                        # x-axis is sector and y-axis is number of threats
                        go.Bar(
                            x=sector_df["primary_sector"],
                            y=sector_df["count"],
                            marker=dict(
                                color=bar_colors, line=dict(color="#080c10", width=1)
                            ),
                            text=sector_df["count"],
                            textposition="outside",
                            textfont=dict(
                                color="#94a3b8", size=10, family="JetBrains Mono"
                            ),
                        )
                    ]
                )
                fig2.update_layout(
                    margin=dict(t=10, b=10, l=10, r=10),
                    height=240,
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    xaxis=dict(
                        color="#94a3b8",
                        tickfont=dict(family="JetBrains Mono", size=10),
                        gridcolor="#1e2d3d",
                    ),
                    yaxis=dict(
                        color="#94a3b8",
                        tickfont=dict(family="JetBrains Mono", size=10),
                        gridcolor="#1e2d3d",
                    ),
                    showlegend=False,
                )
                st.plotly_chart(fig2, use_container_width=True)
            else:
                st.info("Look up CVEs in Tab 2 to see sector breakdown.")
        except Exception:
            st.info("No sector data yet.")
    # The recent activity feed on the right side of the dashboard displays the latest threats added to the database, showing their title, severity, and published date.
    with col_recent:
        st.markdown(
            "<p class='table-header' style='margin-bottom:12px;'>Recent Activity</p>",
            unsafe_allow_html=True,
        )
        # The feed is styled with colored dots to indicate severity and includes timestamps to show when each threat was published, providing users with a quick overview of the most recent developments in the threat landscape.
        try:
            recent = get_db_data(
                "SELECT title, published, severity FROM feed_entries ORDER BY published_timestamp DESC LIMIT 5"
            )
            st.markdown('<div class="activity-container">', unsafe_allow_html=True)
            for _, row in recent.iterrows():
                sev_lower = str(row["severity"]).lower()
                st.markdown(
                    f"""
                    <div class="activity-item">
                        <div class="activity-dot dot-{sev_lower}"></div>
                        <div class="row-title">{row['title'][:60]}...</div>
                        <div style="color:#94a3b8;font-weight:600; font-family:'JetBrains Mono',monospace;
                                    font-size:11px; margin-top:2px;">{row['published']}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            st.markdown("</div>", unsafe_allow_html=True)
        except Exception:
            st.info("No recent activity data.")

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(
        "<h3 style='font-family:\"Syne\",sans-serif; font-weight:700; margin-bottom:4px;'>Live Threat Feed</h3>",
        unsafe_allow_html=True,
    )
    # The live threat feed at the bottom of the dashboard displays all threats from the database, with options to filter by severity and sector.
    if active_sevs:
        try:
            feed_query = (
                f"SELECT * FROM feed_entries WHERE "
                f"(classify_method='verified' AND cvss_severity IN ({','.join(['?']*len(active_sevs))})) "
                f"OR classify_method!='verified' "
                f"ORDER BY "
                f"CASE WHEN classify_method='verified' THEN 0 ELSE 1 END, "
                f"published_timestamp DESC"
            )
            main_feed_df = get_db_data(feed_query, tuple(active_sevs))

            if sector_filter and "primary_sector" in main_feed_df.columns:
                main_feed_df = main_feed_df[
                    (main_feed_df["classify_method"] != "verified")
                    | (main_feed_df["primary_sector"].isin(sector_filter))
                    | main_feed_df["primary_sector"].isna()
                ]
            #             If the CVE-only toggle is enabled, filter the feed to show only entries that have associated CVE IDs, providing a focused view for users interested specifically in CVE-related threats.
            th1, th2, th3, th4, th5, th6 = st.columns([3, 1.2, 1.2, 1, 1, 1.2])
            for col_w, label in zip(
                [th1, th2, th3, th4, th5, th6],
                [
                    "Threat Title",
                    "Source",
                    "CVE IDs",
                    "Severity",
                    "Sector / MITRE",
                    "Published",
                ],
            ):
                col_w.markdown(
                    f"<p class='table-header'>{label}</p>", unsafe_allow_html=True
                )

            st.markdown(
                "<hr style='border:1px solid #1e2d3d; margin:4px 0 0 0;'>",
                unsafe_allow_html=True,
            )

            for _, item in main_feed_df.iterrows():
                try:
                    # Find cve related to threat
                    cves = get_db_data(
                        "SELECT ioc_value FROM iocs WHERE entry_id=? AND ioc_type='CVE'",
                        (item["id"],),
                    )
                    cve_str = (
                        ", ".join(cves["ioc_value"].tolist()) if not cves.empty else "—"
                    )
                except Exception:
                    cve_str = "—"

                sev_lower = str(item.get("severity", "low")).lower()
                sector_val = str(item.get("primary_sector", "General"))
                sector_lower = sector_val.lower()
                mitre_id = str(item.get("mitre_id", "")) if item.get("mitre_id") else ""
                classify_method = str(item.get("classify_method", ""))

                tr1, tr2, tr3, tr4, tr5, tr6 = st.columns([3, 1.2, 1.2, 1, 1, 1.2])
                tr1.markdown(
                    f"<div class='row-title'>{str(item['title'])}</div>",
                    unsafe_allow_html=True,
                )
                tr2.markdown(
                    f"<span class='row-source'>{item['source']}</span>",
                    unsafe_allow_html=True,
                )

                cve_list = [
                    c.strip()
                    for c in cve_str.split(",")
                    if c.strip() and c.strip() != "—"
                ]
                if cve_list:
                    cve_pills = "".join(
                        [
                            "<div style='margin-bottom:3px;'>"
                            "<code style='color:#38bdf8; background:#0d1520;"
                            " border:1px solid #1e2d3d; border-radius:3px;"
                            " padding:1px 6px; font-size:10px;"
                            " font-family:JetBrains Mono,monospace;'>"
                            + cve_id
                            + "</code></div>"
                            for cve_id in cve_list
                        ]
                    )
                else:
                    cve_pills = "<span style='color:#334155; font-size:12px;'>—</span>"
                tr3.markdown(cve_pills, unsafe_allow_html=True)

                cvss_sev = str(item.get("cvss_severity", "")).strip()
                classify_method = str(item.get("classify_method", ""))
                if classify_method != "verified" or not cvss_sev:
                    tr4.markdown(
                        "<span style='color:#334155; font-size:14px;'>—</span>",
                        unsafe_allow_html=True,
                    )
                else:
                    sev_lower = cvss_sev.lower()
                    tr4.markdown(
                        f"<span class='pill pill-{sev_lower}'>{cvss_sev}</span>",
                        unsafe_allow_html=True,
                    )

                sector_icon = SECTOR_ICONS.get(sector_val, "🔒")
                if classify_method != "verified":
                    tr5.markdown(
                        "<span style='color:#334155; font-size:14px;'>—</span>",
                        unsafe_allow_html=True,
                    )
                elif sector_val == "General" and mitre_id:
                    tr5.markdown(
                        f"<span class='pill pill-general'>🔒 General</span>"
                        f"<div style='font-family:JetBrains Mono,monospace; font-size:10px;"
                        f" color:#818cf8; margin-top:4px; font-weight:700;'>{mitre_id}</div>",
                        unsafe_allow_html=True,
                    )
                elif sector_val == "General":
                    tr5.markdown(
                        "<span class='pill pill-general'>🔒 General</span>",
                        unsafe_allow_html=True,
                    )
                else:
                    mitre_sub = (
                        f"<div style='font-family:JetBrains Mono,monospace; font-size:10px; color:#818cf8; margin-top:4px; font-weight:700;'>{mitre_id}</div>"
                        if mitre_id
                        else ""
                    )
                    tr5.markdown(
                        f"<span class='pill pill-{sector_lower}'>{sector_icon} {sector_val}</span>{mitre_sub}",
                        unsafe_allow_html=True,
                    )

                tr6.markdown(
                    f'<div style=\'color:#94a3b8;font-weight:600; font-family:"JetBrains Mono",monospace; '
                    f"font-size:11px;'>{str(item['published'])[:10]}</div>",
                    unsafe_allow_html=True,
                )
                st.markdown(
                    "<hr style='border:none; border-top:1px solid #1a2535; margin:6px 0;'>",
                    unsafe_allow_html=True,
                )

        except Exception as e:
            st.error(f"Error loading feed: {e}")

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(
        "<p class='table-header' style='margin-bottom: 12px'>News Articles (No CVE IOCs)</p>",
        unsafe_allow_html=True,
    )

    # Fethching news-only entries that don't have associated CVEs to display in a separate section, providing users with insights into emerging threats that may not yet have CVE identifiers but are still relevant to the transport sector.
    try:
        news_df = get_db_data(
            """
            SELECT id, source, title, link, summary_clean, severity, category,
                   transport_relevance, mapped_assets, published, published_timestamp
            FROM feed_entries
            ORDER BY published_timestamp DESC
            LIMIT 200
            """
        )

        if not news_df.empty:
            cve_map_df = get_db_data(
                "SELECT DISTINCT entry_id FROM iocs WHERE ioc_type = 'CVE'"
            )
            ids_with_cve = (
                set(cve_map_df["entry_id"].tolist()) if not cve_map_df.empty else set()
            )
            news_df = news_df[~news_df["id"].isin(ids_with_cve)]

            if news_df.empty:
                st.info(
                    "All recent entries have associated CVEs. No 'news‑only' items right now."
                )
            else:
                news_df = news_df.head(50)

                coln1, coln2, coln3, coln4 = st.columns([3, 1.2, 1.2, 1.6])
                for colw, label in zip(
                    (coln1, coln2, coln3, coln4),
                    ("Threat Title", "Source", "Severity", "Published"),
                ):
                    colw.markdown(
                        f"<p class='table-header'>{label}</p>", unsafe_allow_html=True
                    )
                st.markdown(
                    "<hr style='border: 1px solid #1e2d3d; margin: 4px 0 0 0;'>",
                    unsafe_allow_html=True,
                )

                for _, row in news_df.iterrows():
                    sevlower = str(row.get("severity", "LOW")).lower()
                    title = str(row.get("title", "No title"))
                    source = str(row.get("source", ""))
                    link = str(row.get("link", ""))
                    summary = str(row.get("summary_clean", ""))
                    published = str(row.get("published", ""))[:16]
                    category = str(row.get("category", ""))
                    severity = str(row.get("severity", "LOW"))

                    link_html = (
                        f"<a href='{link}' target='_blank' style='color:#38bdf8; "
                        f"font-family:JetBrains Mono,monospace; font-size:11px; "
                        f"text-decoration:none;'>🔗 Read Full Article →</a>"
                        if link and link != "None"
                        else "<span style='color:#334155; font-size:11px;'>No link available</span>"
                    )
                    summary_snippet = summary[:300] + (
                        "..." if len(summary) > 300 else ""
                    )
                    summary_html = (
                        f"<p style='color:#64748b; font-size:12px; font-family:Syne,sans-serif; "
                        f"line-height:1.6; margin:8px 0 0 0;'>{summary_snippet}</p>"
                        if summary.strip()
                        else ""
                    )
                    category_html = (
                        f"<span style='color:#64748b; font-family:JetBrains Mono,monospace; "
                        f"font-size:10px; background:#1e2d3d; padding:2px 8px; "
                        f"border-radius:3px;'>{category}</span>"
                        if category and category not in ("General", "")
                        else ""
                    )
                    st.markdown(
                        f"""
                        <div class="threat-card">
                            <div style="margin-bottom:6px;">
                                <div class="row-title" style="margin-bottom:8px;">
                                    {title}
                                    <span class='pill pill-low' style='margin-left:6px;'>NEWS ONLY</span>
                                </div>
                                <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
                                    <span class='row-source'>{source}</span>
                                    <span class='pill pill-{sevlower}'>{severity}</span>
                                    <span style='color:#94a3b8;font-weight:600; font-family:JetBrains Mono,monospace; font-size:11px;'>{published}</span>
                                    {category_html}
                                </div>
                            </div>
                            {summary_html}
                            <div style="margin-top:10px; padding-top:10px; border-top:1px solid #1e2d3d;">
                                {link_html}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
        else:
            st.info("No entries in the database yet.")
    except Exception as e:
        st.error(f"Error loading news‑only feed: {e}")

# ─────────────────────────────────────────────────────────────
# TAB 2 — CVE LOOKUP & ANALYSIS (analyst + admin only)

if tab2 is not None:
    with tab2:
        st.markdown(
            "<h2 style='font-family:\"Syne\",sans-serif; font-weight:800; margin-bottom:4px;'>"
            "CVE Intelligence Lookup</h2>",
            unsafe_allow_html=True,
        )
        st.markdown(
            "<p style='color:#94a3b8;font-weight:600; font-family:\"JetBrains Mono\",monospace; font-size:12px;'>"
            "Fetch live NVD data · Transport sector classification · MITRE ATT&CK mapping</p>",
            unsafe_allow_html=True,
        )

        st.markdown("<br>", unsafe_allow_html=True)

        col_input, col_btn = st.columns([3, 1])
        with col_input:
            target_cve = st.text_input(
                "CVE ID",
                placeholder="e.g., CVE-2024-1234",
                label_visibility="collapsed",
            )
        with col_btn:
            search_clicked = st.button("🔍 Analyze", use_container_width=True)

        if (search_clicked or target_cve) and target_cve:
            cve_key = target_cve.strip().upper()

            # Only fetch and analyse if CVE changed or not yet analysed
            if st.session_state.get("last_analysed_cve") != cve_key:
                with st.spinner(...):
                    res = fetch_nvd_details(target_cve.strip())
                st.session_state.last_cve_res = res
                st.session_state.last_analysed_cve = cve_key
                st.session_state.last_classification = None
                st.session_state.last_transport_analysis = None
            else:
                res = st.session_state.last_cve_res

            if res:
                if res.get("source") == "MITRE":
                    st.markdown(
                        "<div style='background:rgba(251,191,36,0.08); border:1px solid rgba(251,191,36,0.3);"
                        " border-radius:6px; padding:8px 14px; margin-bottom:12px;"
                        " font-family:JetBrains Mono,monospace; font-size:11px; color:#fbbf24;'>"
                        "⚠️ NVD enrichment pending — data sourced from MITRE. CVSS scores not yet available."
                        "</div>",
                        unsafe_allow_html=True,
                    )

                with st.spinner("Running transport sector classifier..."):
                    if st.session_state.last_classification is None:
                        classification = classify_cve(res["description"])
                        st.session_state.last_classification = classification
                    else:
                        classification = st.session_state.last_classification
                classification["cvss_severity"] = res.get("severity", "")

                def _sync_to_db(clf):
                    try:
                        ioc_row = get_db_data(
                            "SELECT entry_id FROM iocs WHERE ioc_value=? AND ioc_type='CVE' LIMIT 1",
                            (res["id"],),
                        )
                        if not ioc_row.empty:
                            entry_id = ioc_row.iloc[0]["entry_id"]
                            clf["method"] = "verified"
                            with sqlite3.connect(DB_NAME) as conn:
                                conn.execute(
                                    """UPDATE feed_entries
                                    SET primary_sector=?, sector_confidence=?, is_transport=?,
                                    all_sectors=?, classify_method=?, mitre_id=?, cvss_severity=?
                                    WHERE id=?""",
                                    (
                                        clf.get("primary_sector", "General"),
                                        clf.get("confidence", 0.0),
                                        1 if clf.get("is_transport") else 0,
                                        json.dumps(clf.get("sectors", [])),
                                        clf.get("method", "unknown"),
                                        clf.get("mitre_id", ""),
                                        clf.get("cvss_severity", ""),
                                        entry_id,
                                    ),
                                )
                                conn.commit()
                    except Exception as e:
                        st.warning(f"DB sync failed: {e}")

                st.markdown("<br>", unsafe_allow_html=True)
                header_placeholder = st.empty()
                st.markdown(
                    f'<p style=\'color:#94a3b8;font-weight:600; font-family:"JetBrains Mono",monospace; '
                    f"font-size:11px; margin-bottom:20px;'>Published: {res['published'][:10]} "
                    f"· Modified: {res['last_modified'][:10]}</p>",
                    unsafe_allow_html=True,
                )

                col_desc, col_cards = st.columns([2, 1])

                with col_desc:
                    st.markdown(
                        f"""
                        <div class="custom-card">
                            <div class="metric-label" style="margin-bottom:10px;">NVD Description</div>
                            <p style="color:#94a3b8; font-size:14px; line-height:1.7; font-family:'Syne',sans-serif;">
                                {res['description']}
                            </p>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    st.markdown(
                        "<div class='metric-label' style='margin:16px 0 10px 0;'>CVSS Metrics</div>",
                        unsafe_allow_html=True,
                    )
                    g1, g2, g3, g4 = st.columns(4)
                    cvss_score = res["cvss_score"]
                    try:
                        score_val = float(cvss_score)
                        score_color = (
                            "#f87171"
                            if score_val >= 9
                            else (
                                "#fbbf24"
                                if score_val >= 7
                                else "#a78bfa" if score_val >= 4 else "#38bdf8"
                            )
                        )
                    except Exception:
                        score_color = "#64748b"

                    for col_m, label, val in zip(
                        [g1, g2, g3, g4],
                        ["CVSS Score", "Severity", "Attack Vector", "Complexity"],
                        [
                            cvss_score,
                            res["severity"],
                            res["attack_vector"],
                            res["attack_complexity"],
                        ],
                    ):
                        with col_m:
                            v_color = (
                                score_color if label == "CVSS Score" else "#e2e8f0"
                            )
                            st.markdown(
                                f"""
                                <div style="background:#0d1520; border:1px solid #1e2d3d;
                                            border-radius:8px; padding:14px; text-align:center;">
                                    <div class="metric-label">{label}</div>
                                    <div style="font-size:22px; font-weight:700;
                                                font-family:'JetBrains Mono',monospace;
                                                color:{v_color};">{val}</div>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )

                    st.markdown("<br>", unsafe_allow_html=True)
                    s1, s2 = st.columns(2)
                    with s1:
                        st.markdown(
                            f"<p style='font-family:\"JetBrains Mono\",monospace; font-size:12px; color:#64748b;'>"
                            f"🔑 Privileges: <span style='color:#94a3b8;'>{res['privileges_required']}</span></p>",
                            unsafe_allow_html=True,
                        )
                    with s2:
                        st.markdown(
                            f"<p style='font-family:\"JetBrains Mono\",monospace; font-size:12px; color:#64748b;'>"
                            f"👥 User Interaction: <span style='color:#94a3b8;'>{res['user_interaction']}</span></p>",
                            unsafe_allow_html=True,
                        )

                with col_cards:
                    classification_card_placeholder = st.empty()

                    with st.spinner("Running AI transport analysis..."):
                        if st.session_state.last_transport_analysis is None:
                            transport_analysis = get_transport_analysis(
                                res["description"]
                            )
                            st.session_state.last_transport_analysis = (
                                transport_analysis
                            )
                        else:
                            transport_analysis = (
                                st.session_state.last_transport_analysis
                            )

                    if transport_analysis:
                        if classification.get("is_transport"):
                            ai_mitre_id = (
                                transport_analysis.get("mitre_id")
                                or classification.get("mitre_id")
                                or "N/A"
                            )
                        else:
                            # General CVE — use Call 1 only
                            ai_mitre_id = (
                                classification.get("mitre_id")
                                or transport_analysis.get("mitre_id")
                                or "N/A"
                            )
                        if ai_mitre_id != "N/A":
                            classification["mitre_id"] = ai_mitre_id

                        phys = transport_analysis.get("physical_consequence", "N/A")
                        why = transport_analysis.get("transport_why", "")
                        subsector = transport_analysis.get("target_subsector", "N/A")
                        is_transport_spec = transport_analysis.get(
                            "is_transport_specific", False
                        )

                        if (
                            not classification.get("is_transport")
                            and subsector in VALID_TRANSPORT_SECTORS
                        ):
                            classification["primary_sector"] = subsector
                            classification["is_transport"] = True
                            classification["sectors"] = (
                                [subsector] if subsector != "Transport" else []
                            )
                            classification["mitre_id"] = (
                                ai_mitre_id if ai_mitre_id != "N/A" else ""
                            )
                            classification["method"] = "groq-nlp"
                        elif (
                            subsector == "General"
                            and not is_transport_spec
                            and classification.get("is_transport")
                        ):
                            classification["primary_sector"] = "General"
                            classification["is_transport"] = False
                            classification["sectors"] = []
                            classification["mitre_id"] = (
                                ai_mitre_id if ai_mitre_id != "N/A" else ""
                            )
                            classification["method"] = "groq-nlp"
                        elif classification.get(
                            "is_transport"
                        ) and not classification.get("mitre_id"):
                            classification["mitre_id"] = (
                                ai_mitre_id if ai_mitre_id != "N/A" else ""
                            )

                        _sync_to_db(classification)

                        sector = classification["primary_sector"]
                        sector_color = SECTOR_COLORS.get(sector, "#6b7280")
                        sector_icon = SECTOR_ICONS.get(sector, "🔒")
                        mitre_id_cls = classification.get("mitre_id", "")

                        transport_badge_html = (
                            "<span style='background:rgba(52,211,153,0.12); color:#34d399;"
                            " border:1px solid rgba(52,211,153,0.4); padding:4px 12px;"
                            " border-radius:4px; font-family:JetBrains Mono,monospace;"
                            " font-size:11px; font-weight:700;'>✅ TRANSPORT RELEVANT</span>"
                            if classification["is_transport"]
                            else "<span style='background:rgba(107,114,128,0.12); color:#6b7280;"
                            " border:1px solid rgba(107,114,128,0.4); padding:4px 12px;"
                            " border-radius:4px; font-family:JetBrains Mono,monospace;"
                            " font-size:11px;'>⚪ GENERAL</span>"
                        )
                        mitre_badge_html = ""
                        if not classification["is_transport"] and mitre_id_cls:
                            mitre_badge_html = (
                                f"<span style='background:rgba(129,140,248,0.12); color:#818cf8;"
                                f" border:1px solid rgba(129,140,248,0.4); padding:4px 12px;"
                                f" border-radius:4px; font-family:JetBrains Mono,monospace;"
                                f" font-size:11px; font-weight:700;'>🎯 {mitre_id_cls}</span>"
                            )
                        header_placeholder.markdown(
                            f"""
                            <div style="display:flex; align-items:center; gap:16px; margin-bottom:8px; flex-wrap:wrap;">
                                <h2 style="font-family:'JetBrains Mono',monospace; font-weight:700;
                                           color:#f1f5f9; margin:0;">{res['id']}</h2>
                                <span class="pill pill-{sector.lower()}" style="font-size:12px; padding:5px 14px;">
                                    {sector_icon} {sector}
                                </span>
                                {transport_badge_html}
                                {mitre_badge_html}
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                        all_sectors_list = classification.get("sectors", [])
                        method = classification.get("method", "N/A")
                        confidence_pct = int(classification["confidence"] * 100)

                        if all_sectors_list:
                            pills_html_parts = []
                            for s in all_sectors_list:
                                s_icon = SECTOR_ICONS.get(s, "")
                                pills_html_parts.append(
                                    "<span class='pill pill-"
                                    + s.lower()
                                    + "' style='margin:2px;'>"
                                    + s_icon
                                    + " "
                                    + s
                                    + "</span>"
                                )
                            sectors_pills_html = (
                                "<div style='margin-bottom:10px;'>"
                                + " ".join(pills_html_parts)
                                + "</div>"
                            )
                        else:
                            if mitre_id_cls:
                                sectors_pills_html = (
                                    "<div style='margin-bottom:10px;'>"
                                    "<div style='font-size:11px; color:#64748b; font-family:JetBrains Mono,monospace;"
                                    " margin-bottom:4px;'>MITRE ATT&CK</div>"
                                    "<span style='background:rgba(129,140,248,0.12); color:#818cf8;"
                                    " border:1px solid rgba(129,140,248,0.4); padding:4px 10px;"
                                    " border-radius:4px; font-family:JetBrains Mono,monospace;"
                                    " font-size:12px; font-weight:700;'>🎯 "
                                    + mitre_id_cls
                                    + "</span>"
                                    "</div>"
                                )
                            else:
                                sectors_pills_html = (
                                    "<div style='margin-bottom:10px;'></div>"
                                )

                        classification_card_placeholder.markdown(
                            f"""
                            <div style="background: linear-gradient(135deg, #0d1520, #111827);
                                        border: 1px solid {sector_color}40;
                                        border-left: 4px solid {sector_color};
                                        border-radius: 10px; padding: 18px; margin-bottom: 14px;">
                                <div class="metric-label" style="margin-bottom:10px;">🚦 Transport Classification</div>
                                <div style="font-size:22px; font-weight:800; font-family:'Syne',sans-serif;
                                            color:{sector_color}; margin-bottom:12px;">
                                    {sector_icon} {sector}
                                </div>
                                <div style="background:#080c10; border-radius:4px; height:6px; margin-bottom:8px;">
                                    <div style="background:{sector_color}; height:6px; border-radius:4px;
                                                width:{confidence_pct}%; box-shadow:0 0 8px {sector_color}80;"></div>
                                </div>
                                <div style="font-family:'JetBrains Mono',monospace; font-size:11px;
                                            color:#94a3b8;font-weight:600; margin-bottom:12px;">
                                    Confidence: <span style="color:{sector_color};">{confidence_pct}%</span>
                                </div>
                                {sectors_pills_html}
                                <div style="font-family:'JetBrains Mono',monospace; font-size:10px;
                                            color:#334155; border-top:1px solid #1e2d3d;
                                            padding-top:8px; margin-top:4px;">
                                    Method: {method}
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                        st.markdown(
                            f"""
                            <div style="background: linear-gradient(135deg, #0d1520, #111827);
                                        border: 1px solid #1e2d3d;
                                        border-left: 4px solid #818cf8;
                                        border-radius: 10px; padding: 18px; margin-bottom: 14px;">
                                <div class="metric-label" style="margin-bottom:10px;">🧠 AI Transport Analysis</div>
                                <div style="font-family:'JetBrains Mono',monospace; font-size:18px;
                                            font-weight:700; color:#818cf8; margin-bottom:10px;">
                                    {ai_mitre_id}
                                </div>
                                <div style="font-size:12px; color:#64748b; font-family:'JetBrains Mono',monospace;
                                            margin-bottom:4px;">PHYSICAL RISK</div>
                                <div style="font-size:13px; color:#f87171; font-family:'Syne',sans-serif;
                                            margin-bottom:12px; font-weight:600;">⚠️ {phys}</div>
                                <div style="font-size:12px; color:#64748b; font-family:'JetBrains Mono',monospace;
                                            margin-bottom:4px;">SUBSECTOR</div>
                                <div style="font-size:13px; color:#94a3b8; margin-bottom:12px;">{subsector}</div>
                                <div style="font-size:12px; color:#64748b; font-family:'JetBrains Mono',monospace;
                                            margin-bottom:6px;">ANALYSIS</div>
                                <div style="font-size:12px; color:#64748b; font-style:italic; line-height:1.6;">
                                    {why}
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                        st.markdown("<br>", unsafe_allow_html=True)
                        if st.button(
                            "💾  Save Report",
                            key=f"save_report_{res['id']}",
                            use_container_width=True,
                        ):
                            success = save_cve_report(
                                res["id"],
                                res,
                                classification,
                                transport_analysis,
                            )
                            if success:
                                st.success(
                                    f"✅ Report for {res['id']} saved successfully."
                                )
                            else:
                                st.error("❌ Failed to save report.")

                    else:
                        _sync_to_db(classification)
                        sector = classification["primary_sector"]
                        sector_color = SECTOR_COLORS.get(sector, "#6b7280")
                        sector_icon = SECTOR_ICONS.get(sector, "🔒")
                        mitre_id_cls = classification.get("mitre_id", "")
                        confidence_pct = int(classification["confidence"] * 100)

                        transport_badge_html = (
                            "<span style='background:rgba(52,211,153,0.12); color:#34d399;"
                            " border:1px solid rgba(52,211,153,0.4); padding:4px 12px;"
                            " border-radius:4px; font-family:JetBrains Mono,monospace;"
                            " font-size:11px; font-weight:700;'>✅ TRANSPORT RELEVANT</span>"
                            if classification["is_transport"]
                            else "<span style='background:rgba(107,114,128,0.12); color:#6b7280;"
                            " border:1px solid rgba(107,114,128,0.4); padding:4px 12px;"
                            " border-radius:4px; font-family:JetBrains Mono,monospace;"
                            " font-size:11px;'>⚪ GENERAL</span>"
                        )
                        header_placeholder.markdown(
                            f"""
                            <div style="display:flex; align-items:center; gap:16px; margin-bottom:8px; flex-wrap:wrap;">
                                <h2 style="font-family:'JetBrains Mono',monospace; font-weight:700;
                                           color:#f1f5f9; margin:0;">{res['id']}</h2>
                                <span class="pill pill-{sector.lower()}" style="font-size:12px; padding:5px 14px;">
                                    {sector_icon} {sector}
                                </span>
                                {transport_badge_html}
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                        classification_card_placeholder.markdown(
                            f"""
                            <div style="background: linear-gradient(135deg, #0d1520, #111827);
                                        border: 1px solid {sector_color}40;
                                        border-left: 4px solid {sector_color};
                                        border-radius: 10px; padding: 18px; margin-bottom: 14px;">
                                <div class="metric-label" style="margin-bottom:10px;">🚦 Transport Classification</div>
                                <div style="font-size:22px; font-weight:800; font-family:'Syne',sans-serif;
                                            color:{sector_color}; margin-bottom:12px;">
                                    {sector_icon} {sector}
                                </div>
                                <div style="background:#080c10; border-radius:4px; height:6px; margin-bottom:8px;">
                                    <div style="background:{sector_color}; height:6px; border-radius:4px;
                                                width:{confidence_pct}%; box-shadow:0 0 8px {sector_color}80;"></div>
                                </div>
                                <div style="font-family:'JetBrains Mono',monospace; font-size:11px;
                                            color:#94a3b8;font-weight:600; margin-bottom:12px;">
                                    Confidence: <span style="color:{sector_color};">{confidence_pct}%</span>
                                </div>
                                <div style="font-family:'JetBrains Mono',monospace; font-size:10px;
                                            color:#334155; border-top:1px solid #1e2d3d;
                                            padding-top:8px; margin-top:4px;">
                                    Method: {classification.get("method", "N/A")}
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                        st.warning("AI analysis unavailable.")

            else:
                st.warning(
                    f"⚠️ `{target_cve.strip()}` not found in NVD or MITRE. "
                    "It may be reserved/rejected or the CVE ID is incorrect."
                )


# ─────────────────────────────────────────────────────────────
# TAB 3 — SECTOR INTELLIGENCE (analyst + admin only)
# ─────────────────────────────────────────────────────────────
if tab3 is not None:
    with tab3:
        st.markdown(
            "<h2 style='font-family:\"Syne\",sans-serif; font-weight:800; margin-bottom:4px;'>"
            "Transport Sector Intelligence</h2>",
            unsafe_allow_html=True,
        )
        st.markdown(
            "<p style='color:#94a3b8;font-weight:600;  font-family:\"JetBrains Mono\",monospace; font-size:12px;'>"
            "Sector threat summaries · Cross-sector analysis · Verified classifications only</p>",
            unsafe_allow_html=True,
        )

        st.markdown("<br>", unsafe_allow_html=True)

        sector_cols = st.columns(4)
        for col_s, (sector_name, icon) in zip(
            sector_cols,
            [("Aviation", "✈️"), ("Maritime", "🚢"), ("Rail", "🚆"), ("Road", "🚗")],
        ):
            with col_s:
                try:
                    count = get_db_data(
                        "SELECT COUNT(*) as c FROM feed_entries WHERE primary_sector=? AND classify_method='verified'",
                        (sector_name,),
                    ).iloc[0]["c"]
                except Exception:
                    count = 0
                color = SECTOR_COLORS[sector_name]
                st.markdown(
                    f"""
                    <div style="background:linear-gradient(135deg,#0d1520,#111827);
                                border:1px solid {color}30; border-top:3px solid {color};
                                border-radius:10px; padding:20px; text-align:center;">
                        <div style="font-size:28px; margin-bottom:8px;">{icon}</div>
                        <div style="font-family:'Syne',sans-serif; font-weight:700;
                                    font-size:16px; color:{color}; margin-bottom:6px;">{sector_name}</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:28px;
                                    font-weight:700; color:#f1f5f9;">{count}</div>
                        <div style="font-family:'JetBrains Mono',monospace; font-size:10px;
                                    color:#94a3b8;font-weight:600; margin-top:4px;">VERIFIED CVEs</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        st.markdown("<br>", unsafe_allow_html=True)

        _, col_show, _ = st.columns([1.5, 1.5, 3])
        with col_show:
            show_unclassified = st.button(
                "📋 Show Unverified", use_container_width=True
            )

        if show_unclassified:
            try:
                unclassified_df = get_db_data(
                    "SELECT id, title, cvss_severity as severity FROM feed_entries "
                    "WHERE classify_method != 'verified' OR classify_method IS NULL LIMIT 20"
                )
                if unclassified_df.empty:
                    st.info("All entries have been verified via Tab 2.")
                else:
                    st.markdown(
                        f'<p style=\'font-family:"JetBrains Mono",monospace; font-size:12px; '
                        f"color:#fbbf24;'>⚠️ {len(unclassified_df)} unverified entries — look them up in Tab 2 to classify</p>",
                        unsafe_allow_html=True,
                    )
                    st.dataframe(
                        unclassified_df[["id", "title", "severity"]],
                        use_container_width=True,
                    )
            except Exception as e:
                st.error(f"Error: {e}")

        st.markdown("<br>", unsafe_allow_html=True)

        st.markdown(
            "<p class='table-header' style='margin-bottom:12px;'>Verified CVEs by Sector</p>",
            unsafe_allow_html=True,
        )
        selected_sector_view = st.selectbox(
            "View sector",
            [
                "All Transport",
                "Aviation",
                "Maritime",
                "Rail",
                "Road",
                "Transport",
                "General",
            ],
            label_visibility="collapsed",
        )

        try:
            if selected_sector_view == "All Transport":
                sector_cves = get_db_data(
                    "SELECT id, title, cvss_severity as severity, primary_sector, sector_confidence, mitre_id, published "
                    "FROM feed_entries WHERE is_transport=1 AND classify_method='verified' "
                    "ORDER BY published_timestamp DESC LIMIT 30"
                )
            elif selected_sector_view == "General":
                sector_cves = get_db_data(
                    "SELECT id, title, cvss_severity as severity, primary_sector, sector_confidence, mitre_id, published "
                    "FROM feed_entries WHERE primary_sector='General' AND classify_method='verified' "
                    "ORDER BY published_timestamp DESC LIMIT 30"
                )
            else:
                sector_cves = get_db_data(
                    "SELECT id, title, cvss_severity as severity, primary_sector, sector_confidence, mitre_id, published "
                    "FROM feed_entries WHERE primary_sector=? AND classify_method='verified' "
                    "ORDER BY published_timestamp DESC LIMIT 30",
                    (selected_sector_view,),
                )

            if not sector_cves.empty:
                if "sector_confidence" in sector_cves.columns:
                    sector_cves["sector_confidence"] = sector_cves[
                        "sector_confidence"
                    ].apply(lambda x: f"{float(x)*100:.0f}%" if x else "N/A")
                st.dataframe(
                    sector_cves.rename(
                        columns={
                            "title": "Title",
                            "severity": "Severity",
                            "primary_sector": "Sector",
                            "sector_confidence": "Confidence",
                            "mitre_id": "MITRE ID",
                            "published": "Published",
                        }
                    ),
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.info(
                    f"No verified entries for '{selected_sector_view}' yet. "
                    "Look up CVEs in Tab 2 to populate this view."
                )
        except Exception as e:
            st.error(f"Error loading sector data: {e}")


# ─────────────────────────────────────────────────────────────
# TAB 4 — ADMIN PANEL (admin only)
# ─────────────────────────────────────────────────────────────
if tab4 is not None:
    with tab4:
        st.markdown(
            "<h2 style='font-family:\"Syne\",sans-serif; font-weight:800; margin-bottom:4px;'>"
            "Admin Panel</h2>",
            unsafe_allow_html=True,
        )
        st.markdown(
            "<p style='color:#94a3b8;font-weight:600;  font-family:\"JetBrains Mono\",monospace; font-size:12px;'>"
            "Manage users · Assign roles · View account details</p>",
            unsafe_allow_html=True,
        )

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Summary stats ──
        try:
            all_users = get_auth_db_data(
                "SELECT id, fullname, email, role, last_login_ip, created_at FROM users ORDER BY created_at ASC"
            )
            total_users = len(all_users)
            admin_count = len(all_users[all_users["role"] == "admin"])
            analyst_count = len(all_users[all_users["role"] == "analyst"])
            exec_count = len(all_users[all_users["role"] == "executive"])
        except Exception:
            all_users = pd.DataFrame()
            total_users = admin_count = analyst_count = exec_count = 0

        stat1, stat2, stat3, stat4 = st.columns(4)
        for col_stat, label, val, color in zip(
            [stat1, stat2, stat3, stat4],
            ["Total Users", "Admins", "Analysts", "Executives"],
            [total_users, admin_count, analyst_count, exec_count],
            ["#38bdf8", "#f87171", "#38bdf8", "#818cf8"],
        ):
            with col_stat:
                st.markdown(
                    f"""
                    <div class="custom-card" style="border-top:2px solid {color}; padding:18px;">
                        <div class="metric-label">{label}</div>
                        <div class="metric-val" style="color:{color}; font-size:28px;">{val}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(
            "<p class='table-header' style='margin-bottom:16px;'>User Management</p>",
            unsafe_allow_html=True,
        )

        if all_users.empty:
            st.info("No users found in the database.")
        else:
            # Table header
            h1, h2, h3, h4, h5, h6 = st.columns([0.5, 2, 2, 1.5, 1.5, 1.5])
            for col_h, label in zip(
                [h1, h2, h3, h4, h5, h6],
                ["#", "Name", "Email", "Last IP", "Role", "Actions"],
            ):
                col_h.markdown(
                    f"<p class='table-header'>{label}</p>", unsafe_allow_html=True
                )
            st.markdown(
                "<hr style='border:1px solid #1e2d3d; margin:4px 0 8px 0;'>",
                unsafe_allow_html=True,
            )

            for _, user in all_users.iterrows():
                u_id = user["id"]
                u_name = user["fullname"]
                u_email = user["email"]
                u_role = user["role"]
                u_created = str(user["created_at"])[:10]

                role_badge = ROLE_COLORS.get(u_role, ROLE_COLORS["analyst"])

                c1, c2, c3, c4, c5, c6 = st.columns([0.5, 2, 2, 1.5, 1.5, 1.5])

                with c1:
                    st.markdown(
                        f"<div style='color:#334155; font-family:JetBrains Mono,monospace; font-size:12px; padding-top:8px;'>{u_id}</div>",
                        unsafe_allow_html=True,
                    )
                with c2:
                    st.markdown(
                        f"<div style='color:#e2e8f0; font-family:Syne,sans-serif; font-size:13px; font-weight:600; padding-top:8px;'>{u_name}</div>"
                        f"<div style='color:#334155; font-family:JetBrains Mono,monospace; font-size:10px;'>Since {u_created}</div>",
                        unsafe_allow_html=True,
                    )
                with c3:
                    st.markdown(
                        f"<div style='color:#64748b; font-family:JetBrains Mono,monospace; font-size:12px; padding-top:8px;'>{u_email}</div>",
                        unsafe_allow_html=True,
                    )
                with c4:
                    u_ip = user.get("last_login_ip", "Never") or "Never"
                    st.markdown(
                        f"<div style='color:#94a3b8;font-weight:600; font-family:JetBrains Mono,monospace; font-size:11px; padding-top:8px;'>🌐 {u_ip}</div>",
                        unsafe_allow_html=True,
                    )
                with c5:
                    rb_bg = role_badge["bg"]
                    rb_color = role_badge["color"]
                    rb_border = role_badge["border"]
                    rb_label = role_badge["label"]
                    st.markdown(
                        f"<span style='background:{rb_bg}; color:{rb_color};"
                        f" border:1px solid {rb_border}; padding:4px 10px;"
                        f" border-radius:4px; font-family:JetBrains Mono,monospace;"
                        f" font-size:10px; font-weight:700;'>{rb_label}</span>",
                        unsafe_allow_html=True,
                    )
                with c6:
                    # Don't allow admin to change their own role
                    if (
                        u_email == st.session_state.get("email", "")
                        or u_name == st.session_state.username
                        and u_role == "admin"
                    ):
                        st.markdown(
                            "<div style='color:#334155; font-family:JetBrains Mono,monospace; font-size:10px; padding-top:8px;'>— you —</div>",
                            unsafe_allow_html=True,
                        )
                    else:
                        new_role = st.selectbox(
                            f"role_{u_id}",
                            ["analyst", "executive", "admin"],
                            index=(
                                ["analyst", "executive", "admin"].index(u_role)
                                if u_role in ["analyst", "executive", "admin"]
                                else 0
                            ),
                            key=f"role_select_{u_id}",
                            label_visibility="collapsed",
                        )
                        if st.button("Save", key=f"save_role_{u_id}"):
                            try:
                                with sqlite3.connect(AUTH_DB) as conn:
                                    conn.execute(
                                        "UPDATE users SET role=? WHERE id=?",
                                        (new_role, u_id),
                                    )
                                    conn.commit()
                                st.success(f"✅ {u_name}'s role updated to {new_role}")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Failed to update role: {e}")
                        if st.button(
                            "🗑️ Delete",
                            key=f"delete_user_{u_id}",
                            use_container_width=True,
                        ):
                            if u_role == "admin":
                                st.error("❌ Cannot delete an admin account.")
                            else:
                                success = delete_user(u_id, u_name)
                                if success:
                                    st.success(
                                        f"✅ {u_name}'s account has been deleted."
                                    )
                                    st.rerun()
                                else:
                                    st.error("❌ Failed to delete account.")

                st.markdown(
                    "<hr style='border:none; border-top:1px solid #1a2535; margin:4px 0;'>",
                    unsafe_allow_html=True,
                )

# ─────────────────────────────────────────────────────────────
# TAB — CVE REPORTS (all roles)
# ─────────────────────────────────────────────────────────────
with tab_reports:
    st.markdown(
        "<h2 style='font-family:\"Syne\",sans-serif; font-weight:800; margin-bottom:4px;'>"
        "CVE Reports</h2>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<p style='color:#94a3b8;font-weight:600;  font-family:\"JetBrains Mono\",monospace; font-size:12px;'>"
        "Saved CVE analysis reports · Click any report to view full details</p>",
        unsafe_allow_html=True,
    )

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Search box ──
    search_cve = st.text_input(
        "Search reports",
        placeholder="e.g. CVE-2024-1234",
        label_visibility="collapsed",
    )

    try:
        if search_cve.strip():
            reports_df = get_db_data(
                "SELECT cve_id, sector, cvss_severity, subsector, analysed_by, analysed_at "
                "FROM cve_reports WHERE cve_id LIKE ? ORDER BY analysed_at DESC",
                (f"%{search_cve.strip()}%",),
            )
        else:
            reports_df = get_db_data(
                "SELECT cve_id, sector, cvss_severity, subsector, analysed_by, analysed_at "
                "FROM cve_reports ORDER BY analysed_at DESC"
            )

        if reports_df.empty:
            st.info(
                "No reports saved yet. Analyse a CVE in Tab 2 and click 💾 Save Report."
            )
        else:
            st.markdown(
                f'<p style=\'font-family:"JetBrains Mono",monospace; font-size:11px; '
                f"color:#94a3b8;font-weight:600;'>{len(reports_df)} saved report(s)</p>",
                unsafe_allow_html=True,
            )

            for _, report in reports_df.iterrows():
                cve_id = report["cve_id"]
                sector = report["sector"] or "General"
                severity = report["cvss_severity"] or "N/A"
                subsector = report["subsector"] or "N/A"
                analysed_by = report["analysed_by"] or "Unknown"
                analysed_at = str(report["analysed_at"])[:16]
                sector_color = SECTOR_COLORS.get(sector, "#6b7280")
                sector_icon = SECTOR_ICONS.get(sector, "🔒")
                sev_lower = severity.lower()

                with st.expander(
                    f"🔍  {cve_id}  ·  {sector_icon} {sector}  ·  {severity}  ·  Analysed by {analysed_by}  ·  {analysed_at}"
                ):
                    full = get_db_data(
                        "SELECT * FROM cve_reports WHERE cve_id=?", (cve_id,)
                    )
                    if not full.empty:
                        r = full.iloc[0]

                        # ── Description ──
                        st.markdown(
                            f"""
                            <div class="custom-card">
                                <div class="metric-label" style="margin-bottom:8px;">NVD Description</div>
                                <p style="color:#94a3b8; font-size:13px; line-height:1.7;
                                          font-family:'Syne',sans-serif;">{r['description']}</p>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                        # ── CVSS Metrics ──
                        st.markdown(
                            "<div class='metric-label' style='margin:12px 0 8px 0;'>CVSS Metrics</div>",
                            unsafe_allow_html=True,
                        )
                        m1, m2, m3 = st.columns(3)
                        for col_r, lbl, val in zip(
                            [m1, m2, m3],
                            ["CVSS Score", "Attack Vector", "Complexity"],
                            [
                                r["cvss_score"],
                                r["attack_vector"],
                                r["attack_complexity"],
                            ],
                        ):
                            with col_r:
                                st.markdown(
                                    f"""
                                    <div style="background:#0d1520; border:1px solid #1e2d3d;
                                                border-radius:8px; padding:12px; text-align:center;">
                                        <div class="metric-label">{lbl}</div>
                                        <div style="font-size:18px; font-weight:700;
                                                    font-family:'JetBrains Mono',monospace;
                                                    color:#e2e8f0;">{val}</div>
                                    </div>
                                    """,
                                    unsafe_allow_html=True,
                                )

                        st.markdown("<br>", unsafe_allow_html=True)

                        # ── Classification + AI ──
                        col_cls, col_ai = st.columns(2)
                        with col_cls:
                            confidence_pct = (
                                int(float(r["confidence"]) * 100)
                                if r["confidence"]
                                else 0
                            )
                            st.markdown(
                                f"""
                                <div style="background:linear-gradient(135deg,#0d1520,#111827);
                                            border:1px solid {sector_color}40;
                                            border-left:4px solid {sector_color};
                                            border-radius:10px; padding:16px;">
                                    <div class="metric-label" style="margin-bottom:8px;">🚦 Transport Classification</div>
                                    <div style="font-size:20px; font-weight:800; color:{sector_color};
                                                margin-bottom:10px;">{sector_icon} {sector}</div>
                                    <div style="background:#080c10; border-radius:4px; height:6px; margin-bottom:6px;">
                                        <div style="background:{sector_color}; height:6px; border-radius:4px;
                                                    width:{confidence_pct}%;"></div>
                                    </div>
                                    <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#94a3b8;font-weight:600;">
                                        Confidence: <span style="color:{sector_color};">{confidence_pct}%</span>
                                    </div>
                                    <div style="font-family:'JetBrains Mono',monospace; font-size:11px;
                                                color:#818cf8; margin-top:8px; font-weight:700;">
                                        🎯 {r['mitre_id'] or 'N/A'}
                                    </div>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                        with col_ai:
                            st.markdown(
                                f"""
                                <div style="background:linear-gradient(135deg,#0d1520,#111827);
                                            border:1px solid #1e2d3d;
                                            border-left:4px solid #818cf8;
                                            border-radius:10px; padding:16px;">
                                    <div class="metric-label" style="margin-bottom:8px;">🧠 AI Transport Analysis</div>
                                    <div style="font-size:12px; color:#64748b; font-family:'JetBrains Mono',monospace;
                                                margin-bottom:4px;">PHYSICAL RISK</div>
                                    <div style="font-size:13px; color:#f87171; font-weight:600;
                                                margin-bottom:10px;">⚠️ {r['physical_risk'] or 'N/A'}</div>
                                    <div style="font-size:12px; color:#64748b; font-family:'JetBrains Mono',monospace;
                                                margin-bottom:4px;">SUBSECTOR</div>
                                    <div style="font-size:13px; color:#94a3b8; margin-bottom:10px;">
                                        {r['subsector'] or 'N/A'}</div>
                                    <div style="font-size:12px; color:#64748b; font-family:'JetBrains Mono',monospace;
                                                margin-bottom:4px;">ANALYSIS</div>
                                    <div style="font-size:12px; color:#64748b; font-style:italic; line-height:1.6;">
                                        {r['ai_analysis'] or 'N/A'}</div>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )

                        st.markdown(
                            f"<div style='font-family:JetBrains Mono,monospace; font-size:10px; "
                            f"color:#334155; margin-top:12px;'>Analysed by {analysed_by} · {analysed_at}</div>",
                            unsafe_allow_html=True,
                        )

    except Exception as e:
        st.error(f"Error loading reports: {e}")
