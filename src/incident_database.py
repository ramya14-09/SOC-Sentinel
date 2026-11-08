
import sqlite3
from pathlib import Path


# --------------------------------------------------
# DATABASE CONFIGURATION
# --------------------------------------------------

DB_PATH = Path(__file__).resolve().parent.parent / "incidents.db"


# --------------------------------------------------
# CREATE INCIDENT TABLE
# --------------------------------------------------

def initialize_database():

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            threat TEXT NOT NULL,
            user TEXT,
            ip_address TEXT,
            risk_level TEXT,
            risk_score INTEGER,
            status TEXT DEFAULT 'Open',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


# --------------------------------------------------
# SAVE OR UPDATE INCIDENT
# --------------------------------------------------

def save_incident(
    incident_id,
    threat,
    user,
    ip_address,
    risk_level,
    risk_score,
    status
):

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO incidents (
            incident_id,
            threat,
            user,
            ip_address,
            risk_level,
            risk_score,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)

        ON CONFLICT(incident_id)
        DO UPDATE SET
            status = excluded.status,
            risk_level = excluded.risk_level,
            risk_score = excluded.risk_score
    """, (
        str(incident_id),
        str(threat),
        str(user),
        str(ip_address),
        str(risk_level),
        int(risk_score),
        str(status)
    ))

    connection.commit()
    connection.close()


# --------------------------------------------------
# LOAD ALL INCIDENTS
# --------------------------------------------------

def get_all_incidents():

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM incidents
        ORDER BY created_at DESC
    """)

    rows = cursor.fetchall()

    columns = [
        "Incident ID",
        "Threat",
        "User",
        "IP Address",
        "Risk Level",
        "Risk Score",
        "Status",
        "Created At"
    ]

    connection.close()

    import pandas as pd

    return pd.DataFrame(rows, columns=columns)
