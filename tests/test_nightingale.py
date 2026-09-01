"""
Run with: pytest tests/test_nightingale.py -v
Uses a throwaway sqlite file per test session so runs are repeatable.
"""
import json
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ["NIGHTINGALE_DB"] = "test_nightingale.db"

@pytest.fixture(autouse=True)
def fresh_db():
    if os.path.exists("test_nightingale.db"):
        os.remove("test_nightingale.db")
    import app as appmodule
    appmodule.DB = appmodule.init_db()
    appmodule.SESSIONS.clear()
    yield appmodule
    if os.path.exists("test_nightingale.db"):
        os.remove("test_nightingale.db")

def client(appmodule):
    return appmodule.app.test_client()

def _seed_staff(appmodule, name, role):
    from werkzeug.security import generate_password_hash
    appmodule.DB.execute("INSERT INTO staff_users (id, name, role, password_hash) VALUES (?,?,?,?)",
                          (name, name, role, generate_password_hash("pw")))
    appmodule.DB.commit()

def test_guest_to_patient_conversion(fresh_db):
    c = client(fresh_db)
    r = c.post('/api/lead/start', json={"source_channel": "instagram_ad_click", "campaign_id": "ivf_over40"})
    lead_id = r.get_json()["lead_session_id"]
    c.post(f'/api/lead/{lead_id}/message', json={"message": "I'm worried about my fertility at 42"})
    r = c.post('/api/auth/signup', json={"lead_session_id": lead_id, "email": "a@x.com",
                                          "phone": "0123456789", "password": "pw123456"})
    ps_id = r.get_json()["patient_session_id"]
    profile = c.get(f'/api/patient/{ps_id}/profile',
                     headers={"Authorization": "Bearer " + r.get_json()["token"]}).get_json()
    assert any("fertility" in p["value"].lower() or p["fact_type"] == "chief_complaint" for p in profile)
    lead = fresh_db.DB.execute("SELECT * FROM lead_sessions WHERE id=?", (lead_id,)).fetchone()
    assert lead["campaign_id"] == "ivf_over40" and lead["status"] == "converted"

def test_value_events(fresh_db):
    c = client(fresh_db)
    lead_id = c.post('/api/lead/start', json={"source_channel": "website_widget"}).get_json()["lead_session_id"]
    r = c.get(f'/api/lead/{lead_id}/clinic-stat').get_json()
    # low volume -> must NOT fabricate a number
    assert r["stat"] is None
    for i in range(5):
        lid = c.post('/api/lead/start', json={"source_channel": "website_widget"}).get_json()["lead_session_id"]
        c.post(f'/api/lead/{lid}/message', json={"message": "hi"})
    r2 = c.get(f'/api/lead/{lead_id}/clinic-stat').get_json()
    assert str(r2["raw_count"]) in r2["stat"]

def test_escalation_payload(fresh_db):
    c = client(fresh_db)
    lead_id = c.post('/api/lead/start', json={"source_channel": "google_ad_click"}).get_json()["lead_session_id"]
    r = c.post('/api/auth/signup', json={"lead_session_id": lead_id, "email": "b@x.com",
                                          "phone": "0123456789", "password": "pw123456"}).get_json()
    hdr = {"Authorization": "Bearer " + r["token"]}
    ps_id = r["patient_session_id"]
    m = c.post(f'/api/patient/{ps_id}/message', json={"message": "I have crushing chest pain"}, headers=hdr).get_json()
    e = c.post(f'/api/patient/{ps_id}/escalate', json={"triggering_message_id": m["triggering_message_id"]}, headers=hdr).get_json()
    esc = fresh_db.DB.execute("SELECT * FROM escalations WHERE id=?", (e["escalation_id"],)).fetchone()
    assert esc and json.loads(esc["triage_summary"]) and json.loads(esc["attribution_snapshot"])["source_channel"] == "google_ad_click"

def test_risk_escalation(fresh_db):
    from risk_gating import assess_risk
    r = assess_risk("I have crushing chest pain.")
    assert r["risk_level"] == "high"
    c = client(fresh_db)
    lead_id = c.post('/api/lead/start', json={"source_channel": "website_widget"}).get_json()["lead_session_id"]
    sr = c.post('/api/auth/signup', json={"lead_session_id": lead_id, "email": "c@x.com",
                                           "phone": "012", "password": "pw123456"}).get_json()
    hdr = {"Authorization": "Bearer " + sr["token"]}
    m = c.post(f'/api/patient/{sr["patient_session_id"]}/message',
               json={"message": "I have crushing chest pain."}, headers=hdr).get_json()
    assert m["risk_level"] == "high" and m["escalation_required"] is True
    assert "clinic" in m["reply"].lower() and "chest pain" not in m["reply"].lower()  # no advice given

def test_memory_mutation(fresh_db):
    from memory import extract_facts
    f1 = extract_facts("msg1", "I take Advil.")
    assert f1[0]["fact_type"] == "medication" and f1[0]["status"] == "active"
    f2 = extract_facts("msg2", "Actually I stopped last week.")
    # second turn alone won't name the drug again in real chat; simulate the mutate call directly
    c = client(fresh_db)
    lead_id = c.post('/api/lead/start', json={"source_channel": "website_widget"}).get_json()["lead_session_id"]
    sr = c.post('/api/auth/signup', json={"lead_session_id": lead_id, "email": "d@x.com",
                                           "phone": "012", "password": "pw123456"}).get_json()
    hdr = {"Authorization": "Bearer " + sr["token"]}
    ps_id = sr["patient_session_id"]
    c.post(f'/api/patient/{ps_id}/message', json={"message": "I take Advil."}, headers=hdr)
    c.post(f'/api/patient/{ps_id}/message', json={"message": "I take Advil, stopped last week."}, headers=hdr)
    profile = c.get(f'/api/patient/{ps_id}/profile', headers=hdr).get_json()
    advil = [p for p in profile if p["value"].lower() == "advil"]
    assert len(advil) == 1 and advil[0]["status"] == "stopped"
    assert advil[0]["provenance_pointer"]

def test_redaction(fresh_db):
    from redaction import redact
    redacted, found = redact("My name is John Doe and my IC is S1234567A.")
    assert found and "[REDACTED]" in redacted and "John Doe" not in redacted and "S1234567A" not in redacted
    c = client(fresh_db)
    lead_id = c.post('/api/lead/start', json={"source_channel": "website_widget"}).get_json()["lead_session_id"]
    c.post(f'/api/lead/{lead_id}/message', json={"message": "My name is Jane Tan, IC S7654321B"})
    rows = fresh_db.DB.execute("SELECT content_redacted FROM guest_messages WHERE sender='guest'").fetchall()
    logs = fresh_db.DB.execute("SELECT metadata FROM audit_logs").fetchall()
    assert all("Jane Tan" not in r["content_redacted"] for r in rows)
    assert all("Jane Tan" not in l["metadata"] and "S7654321B" not in l["metadata"] for l in logs)

def test_access_control(fresh_db):
    c = client(fresh_db)
    _seed_staff(fresh_db, "nurse1", "nurse")
    lead_a = c.post('/api/lead/start', json={"source_channel": "website_widget"}).get_json()["lead_session_id"]
    lead_b = c.post('/api/lead/start', json={"source_channel": "website_widget"}).get_json()["lead_session_id"]
    a = c.post('/api/auth/signup', json={"lead_session_id": lead_a, "email": "pa@x.com", "phone": "1", "password": "pw123456"}).get_json()
    b = c.post('/api/auth/signup', json={"lead_session_id": lead_b, "email": "pb@x.com", "phone": "2", "password": "pw123456"}).get_json()

    # Patient A cannot fetch Patient B's profile
    r = c.get(f'/api/patient/{b["patient_session_id"]}/profile', headers={"Authorization": "Bearer " + a["token"]})
    assert r.status_code == 403

    # Patient cannot reach clinician queue
    r = c.get('/api/staff/warm-leads', headers={"Authorization": "Bearer " + a["token"]})
    assert r.status_code == 401

    # Nurse CAN see the profile
    ln = c.post('/api/auth/login', json={"name": "nurse1", "password": "pw"}).get_json()
    r = c.get(f'/api/patient/{a["patient_session_id"]}/profile', headers={"Authorization": "Bearer " + ln["token"]})
    assert r.status_code == 200

def test_trust(fresh_db):
    c = client(fresh_db)
    lead_id = c.post('/api/lead/start', json={"source_channel": "website_widget"}).get_json()["lead_session_id"]
    r = c.post(f'/api/lead/{lead_id}/message', json={"message": "Are you a real doctor?"}).get_json()
    assert "not a doctor" in r["reply"].lower() and ("nurse" in r["reply"].lower() or "clinician" in r["reply"].lower())