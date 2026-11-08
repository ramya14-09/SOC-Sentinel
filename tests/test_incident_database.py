
import src.incident_database as incident_db


def test_save_and_retrieve_incident(tmp_path, monkeypatch):
    test_db = tmp_path / "test_incidents.db"

    monkeypatch.setattr(incident_db, "DB_PATH", test_db)

    incident_db.initialize_database()

    incident_db.save_incident(
        incident_id="INC001",
        threat="Brute Force Attack",
        user="ramya",
        ip_address="192.0.2.10",
        risk_level="HIGH",
        risk_score=75,
        status="Open"
    )

    incidents = incident_db.get_all_incidents()

    assert len(incidents) == 1
    assert incidents.iloc[0]["Incident ID"] == "INC001"
    assert incidents.iloc[0]["Threat"] == "Brute Force Attack"
    assert incidents.iloc[0]["Status"] == "Open"


def test_update_incident_status(tmp_path, monkeypatch):
    test_db = tmp_path / "test_incidents.db"

    monkeypatch.setattr(incident_db, "DB_PATH", test_db)

    incident_db.initialize_database()

    incident_db.save_incident(
        "INC002", "Password Spraying", "admin",
        "192.0.2.20", "HIGH", 80, "Open"
    )

    incident_db.save_incident(
        "INC002", "Password Spraying", "admin",
        "192.0.2.20", "HIGH", 80, "Resolved"
    )

    incidents = incident_db.get_all_incidents()

    assert len(incidents) == 1
    assert incidents.iloc[0]["Status"] == "Resolved"
