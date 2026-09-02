import sqlite3
import os

DB_PATH = os.environ.get("NIGHTINGALE_DB", "nightingale.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS lead_sessions (
    id TEXT PRIMARY KEY, clinic_id TEXT, source_channel TEXT, campaign_id TEXT,
    creative TEXT, identity_level TEXT, handle TEXT, email TEXT, context TEXT,
    status TEXT DEFAULT 'active', landing_timestamp TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS guest_messages (
    id TEXT PRIMARY KEY, lead_session_id TEXT, sender TEXT, content_redacted TEXT,
    phi_detected INTEGER DEFAULT 0, encrypted_raw BLOB,
    audio_transcript_id TEXT, audio_url TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS value_events (
    id TEXT PRIMARY KEY, lead_session_id TEXT, event_type TEXT, content TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS patients (
    id TEXT PRIMARY KEY, email TEXT UNIQUE, phone TEXT, password_hash TEXT,
    email_verified INTEGER DEFAULT 0, phone_verified INTEGER DEFAULT 0,
    verification_code TEXT,
    marketing_consent INTEGER DEFAULT 0, marketing_consent_ts TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS patient_sessions (
    id TEXT PRIMARY KEY, patient_id TEXT, lead_session_id TEXT,
    consent_share_ts TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY, patient_session_id TEXT, sender TEXT, content_redacted TEXT,
    risk_level TEXT, risk_reason TEXT, confidence TEXT, risk_provenance TEXT,
    source_guest_message_id TEXT, audio_transcript_id TEXT, audio_url TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS memory_items (
    id TEXT PRIMARY KEY, patient_session_id TEXT, fact_type TEXT, value TEXT,
    status TEXT, provenance_pointer TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS escalations (
    id TEXT PRIMARY KEY, patient_session_id TEXT, triggering_message_id TEXT,
    triage_summary TEXT, profile_snapshot TEXT, attribution_snapshot TEXT,
    status TEXT DEFAULT 'pending', clinician_response TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS funnel_events (
    id TEXT PRIMARY KEY, lead_session_id TEXT, patient_session_id TEXT,
    event_type TEXT, metadata TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY, actor_hash TEXT, action TEXT, target_hash TEXT,
    metadata TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS staff_users (
    id TEXT PRIMARY KEY, name TEXT, role TEXT, password_hash TEXT
);
CREATE TABLE IF NOT EXISTS staff_referrals (
    id TEXT PRIMARY KEY, staff_id TEXT, topic TEXT, token TEXT UNIQUE,
    used INTEGER DEFAULT 0, created_at TEXT
);
"""

def get_db(path=None):
    conn = sqlite3.connect(path or DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db(path=None):
    conn = get_db(path)

    conn.executescript(SCHEMA)

    # Migrate existing databases to the current patients schema
    try:
        conn.execute("ALTER TABLE patients ADD COLUMN email_verified INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute("ALTER TABLE patients ADD COLUMN phone_verified INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute("ALTER TABLE patients ADD COLUMN verification_code TEXT")
    except sqlite3.OperationalError:
        pass

    conn.commit()

    return conn