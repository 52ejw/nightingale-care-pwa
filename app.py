"""
Nightingale backend. A simple Flask app that uses 
bearer tokens for login and checks user roles and access on the server.
Audit logs store only hashes and metadata, never raw patient messages.
"""
import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, g, jsonify, request, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash

from db import init_db
from channel_rules import resolve_opening
from redaction import redact, encrypt, decrypt
from risk_gating import assess_risk
from memory import extract_facts, merge_into_profile

# App configuration, database, authentication sessions, guest rate limits, and session expiry.
app = Flask(__name__, static_folder="static", static_url_path="")
DB = init_db()
SESSIONS: dict[str, dict] = {}          
GUEST_RATE_LIMIT: dict[str, list] = {}  
GUEST_TTL_DAYS = 30                     

# small helpers

def now_iso(): return datetime.now(timezone.utc).isoformat()

def new_id(): return str(uuid.uuid4())

def audit(actor_id, action, target_id, meta=None):
    DB.execute(
        "INSERT INTO audit_logs (id, actor_hash, action, target_hash, metadata, created_at) VALUES (?,?,?,?,?,?)",
        (new_id(),
         hashlib.sha256((actor_id or "anon").encode()).hexdigest()[:16],
         action,
         hashlib.sha256((target_id or "").encode()).hexdigest()[:16],
         json.dumps(meta or {}), now_iso())
    )
    DB.commit()

def emit_event(lead_id=None, patient_session_id=None, event_type="", meta=None):
    DB.execute(
        "INSERT INTO funnel_events (id, lead_session_id, patient_session_id, event_type, metadata, created_at) VALUES (?,?,?,?,?,?)",
        (new_id(), lead_id, patient_session_id, event_type, json.dumps(meta or {}), now_iso())
    )
    DB.commit()

def require_role(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            sess = SESSIONS.get(token)
            if not sess or sess["role"] not in roles:
                audit(sess["id"] if sess else None, "unauthorized_access_attempt", request.path, {"needed": roles})
                return jsonify({"error": "unauthorized"}), 401
            g.session = sess
            return f(*a, **kw)
        return wrapper
    return deco

def rate_limited(lead_id, max_per_min=10):
    now = datetime.now(timezone.utc)
    hits = [t for t in GUEST_RATE_LIMIT.get(lead_id, []) if now - t < timedelta(minutes=1)]
    hits.append(now)
    GUEST_RATE_LIMIT[lead_id] = hits
    return len(hits) > max_per_min

# static frontend

@app.get("/")
def index():
    return send_from_directory("static", "index.html")

# channels and attribution

@app.post("/api/lead/start")
def lead_start():
    body = request.get_json(force=True)
    channel = body.get("source_channel")
    identity_level = "identified" if body.get("email") or body.get("handle") else "anonymous"
    lead_id = new_id()
    DB.execute(
        "INSERT INTO lead_sessions (id, clinic_id, source_channel, campaign_id, creative, identity_level, "
        "handle, email, context, landing_timestamp, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (lead_id, body.get("clinic_id", "sunway_whf"), channel, body.get("campaign_id"),
         body.get("creative"), identity_level, body.get("handle"), body.get("email"),
         body.get("context", "your visit"), now_iso(), now_iso())
    )
    DB.commit()
    opening = resolve_opening(channel, identity_level, topic=body.get("context", "your visit"),
                               name=body.get("name"), staff_name=body.get("staff_name"))
    emit_event(lead_id=lead_id, event_type="visitor", meta={"channel": channel})
    emit_event(lead_id=lead_id, event_type="conversation_started")
    return jsonify({"lead_session_id": lead_id, "greeting": opening["greeting"],
                     "value_events_offered": opening["value_events_offered"]})

@app.post("/api/staff/referral")
@require_role("staff", "clinician", "nurse")
def staff_referral():
    body = request.get_json(force=True)
    token = secrets.token_urlsafe(8)
    DB.execute(
        "INSERT INTO staff_referrals (id, staff_id, topic, token, created_at) VALUES (?,?,?,?,?)",
        (new_id(), g.session["id"], body["topic"], token, now_iso())
    )
    DB.commit()
    audit(g.session["id"], "staff_referral_created", token, {"topic": body["topic"]})
    return jsonify({"link": f"/?ref={token}"})

@app.get("/api/lead/from-referral/<token>")
def lead_from_referral(token):
    row = DB.execute("SELECT * FROM staff_referrals WHERE token=?", (token,)).fetchone()
    if not row:
        return jsonify({"error": "invalid link"}), 404
    resp = lead_start_internal(channel="staff_referral", identity_level="identified",
                                context=row["topic"], staff_name="the clinic team")
    return jsonify(resp)

def lead_start_internal(**kw):
    lead_id = new_id()
    DB.execute(
        "INSERT INTO lead_sessions (id, clinic_id, source_channel, identity_level, context, landing_timestamp, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (lead_id, "sunway_whf", kw["channel"], kw["identity_level"], kw["context"], now_iso(), now_iso())
    )
    DB.commit()
    opening = resolve_opening(kw["channel"], kw["identity_level"], topic=kw["context"],
                               staff_name=kw.get("staff_name"))
    emit_event(lead_id=lead_id, event_type="visitor", meta={"channel": kw["channel"]})
    return {"lead_session_id": lead_id, "greeting": opening["greeting"]}

"""
Simulates a webhook triggered by a comment on a clinic post.
Only the user's handle is known, so they remain anonymous.
A like alone does not create a LeadSession because it shows no expressed interest.
"""
@app.post("/api/webhook/social_comment")
def social_comment_webhook():
    body = request.get_json(force=True)
    platform = body["platform"]  # instagram_comment | tiktok_comment | facebook_comment
    resp = lead_start_internal(channel=platform, identity_level="anonymous",
                                context=body.get("post_topic", "your comment"))
    return jsonify({"dm_sent": True, "portal_link": f"/?lead={resp['lead_session_id']}",
                     "opening": resp["greeting"]})

# Guest value and scope boundary

VALUE_KB = {
    "egg freezing": "Egg freezing (oocyte cryopreservation) involves ovarian stimulation, egg retrieval, then vitrification — most clinics quote a 2-3 week process per cycle.",
    "ivf": "IVF success rates vary strongly by age and clinic — ask for the clinic's own live-birth-per-cycle rate by age band, not just the national average.",
    "fertility": "A basic fertility workup usually starts with hormone bloodwork and a semen analysis where relevant, before anything more invasive.",
}

def guest_reply(lead_id, text_redacted):
    low = text_redacted.lower()
    if "real doctor" in low or "are you a bot" in low or "are you human" in low:
        return ("I'm Nightingale, an AI assistant built for this clinic — I'm not a doctor and I don't diagnose. "
                "I can answer general questions and pass anything clinical to a real nurse or clinician, usually within 12-18 hours. "
                "You're chatting with software right now, and I'll always tell you when a human takes over."), "trust_response"
    for topic, fact in VALUE_KB.items():
        if topic in low:
            return (f"{fact} I can't say what's right for your specific situation, but a clinician can once you're ready to share more."), "education"
    return ("Happy to help — I can share general info on services, hours, and what to expect, "
            "all without needing an account yet. What would you like to know?"), "education"

@app.post("/api/lead/<lead_id>/message")
def guest_message(lead_id):
    lead = DB.execute("SELECT * FROM lead_sessions WHERE id=?", (lead_id,)).fetchone()
    if not lead:
        return jsonify({"error": "not found"}), 404
    if rate_limited(lead_id):
        return jsonify({"error": "rate_limited", "message": "Too many messages — please slow down a moment."}), 429

    raw = request.get_json(force=True)["message"]
    redacted, phi_found = redact(raw)
    risk = assess_risk(redacted)
    enc = encrypt(raw) if phi_found else None  # PHI hidden from staff until consent

    DB.execute(
        "INSERT INTO guest_messages (id, lead_session_id, sender, content_redacted, phi_detected, encrypted_raw, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (new_id(), lead_id, "guest", redacted, int(phi_found), enc, now_iso())
    )
    DB.commit()
    audit(None, "guest_message_received", lead_id, {"phi_detected": phi_found})

    if risk["risk_level"] in ("high", "medium"):
        reply = (
            "I want to make sure the right person sees this rather than me guessing. "
            "Because you've mentioned something that may need clinical attention, "
            "I'm not going to give you a generic answer. "
            "I can help send this to the clinic so a nurse or clinician can review it."
        )
        event_type = "clinical_escalation"
    else:
        reply, event_type = guest_reply(lead_id, redacted)

    msg_id = new_id()
    DB.execute(
        "INSERT INTO guest_messages (id, lead_session_id, sender, content_redacted, created_at) VALUES (?,?,?,?,?)",
        (msg_id, lead_id, "assistant", reply, now_iso())
    )
    DB.execute(
        "INSERT INTO value_events (id, lead_session_id, event_type, content, created_at) VALUES (?,?,?,?,?)",
        (new_id(), lead_id, event_type, reply, now_iso())
    )
    DB.commit()
    emit_event(lead_id=lead_id, event_type="value_event", meta={"kind": event_type})
    return jsonify({"reply": reply, "value_event": event_type, "trust_prompt_available": True})

"""
Creates a short, personalised note based on what the user actually said.
Limited to 240 characters as required by the brief.
"""
@app.get("/api/lead/<lead_id>/personal-note")
def personal_note(lead_id):
    rows = DB.execute(
        "SELECT content_redacted FROM guest_messages WHERE lead_session_id=? AND sender='guest' ORDER BY created_at DESC LIMIT 1",
        (lead_id,)
    ).fetchone()
    topic = "this" if not rows else rows["content_redacted"][:30]
    note = (f"We know it's hard to bring up {topic.lower()}. Most people who ask about it "
            f"aren't sure where to start either — and asking is already the hard part done. "
            f"You can share this privately, or with someone you trust.")[:240]
    DB.execute("INSERT INTO value_events (id, lead_session_id, event_type, content, created_at) VALUES (?,?,?,?,?)",
               (new_id(), lead_id, "personal_note", note, now_iso()))
    DB.commit()
    emit_event(lead_id=lead_id, event_type="value_event", meta={"kind": "personal_note"})
    return jsonify({"note": note, "chars": len(note)})

"""
Value event: Shows how many people asked this clinic a question this week.
Uses a live count and only displays it when the number is meaningful.
This query is tested by test_value_events.py.
"""
@app.get("/api/lead/<lead_id>/clinic-stat")
def clinic_stat(lead_id):
    since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    lead = DB.execute("SELECT clinic_id FROM lead_sessions WHERE id=?", (lead_id,)).fetchone()
    count = DB.execute(
        "SELECT COUNT(DISTINCT lead_session_id) c FROM guest_messages gm "
        "JOIN lead_sessions ls ON ls.id = gm.lead_session_id "
        "WHERE gm.sender='guest' AND gm.created_at >= ? AND ls.clinic_id = ?",
        (since, lead["clinic_id"] if lead else "sunway_whf")
    ).fetchone()["c"]
    if count < 3:
        return jsonify({"stat": None, "reason": "sample too small to show honestly", "raw_count": count})
    stat = f"{count} people asked this clinic a question this week."
    return jsonify({"stat": stat, "raw_count": count})

# Conversion and Identity 

"""
Authentication happens when the user shows interest or receives value.
Guest context is moved into the new PatientSession with its original source,
so the patient does not need to repeat what they already shared.
"""
@app.post("/api/auth/signup")
def signup():
    body = request.get_json(force=True)
    lead_id = body["lead_session_id"]
    email, phone = body["email"], body["phone"]
    lead = DB.execute("SELECT * FROM lead_sessions WHERE id=?", (lead_id,)).fetchone()
    if not lead:
        return jsonify({"error": "lead not found"}), 404

    patient = DB.execute("SELECT * FROM patients WHERE email=?", (email,)).fetchone()
    if not patient:
        patient_id = new_id()  # immutable internal PK; email/phone can change later without breaking this
        DB.execute(
            "INSERT INTO patients (id, email, phone, password_hash, marketing_consent, marketing_consent_ts, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (patient_id, email, phone, generate_password_hash(body["password"]),
             int(body.get("marketing_consent", False)),
             now_iso() if body.get("marketing_consent") else None, now_iso())
        )
    else:
        patient_id = patient["id"]
    DB.commit()

    ps_id = new_id()
    DB.execute(
        "INSERT INTO patient_sessions (id, patient_id, lead_session_id, consent_share_ts, created_at) VALUES (?,?,?,?,?)",
        (ps_id, patient_id, lead_id, now_iso(), now_iso())
    )
    DB.execute("UPDATE lead_sessions SET status='converted' WHERE id=?", (lead_id,))
    DB.commit()

    # Moves approved guest facts into the patient session while keeping the original guest message as their source.
    guest_msgs = DB.execute(
        "SELECT * FROM guest_messages WHERE lead_session_id=? AND sender='guest' ORDER BY created_at", (lead_id,)
    ).fetchall()
    for gm in guest_msgs:
        facts = extract_facts(gm["id"], gm["content_redacted"])  # provenance_pointer stays the GuestMessage id
        merge_into_profile(DB, ps_id, facts)

    token = secrets.token_urlsafe(24)
    SESSIONS[token] = {"type": "patient", "id": patient_id, "role": "patient", "patient_session_id": ps_id}
    emit_event(lead_id=lead_id, patient_session_id=ps_id, event_type="auth_started")
    emit_event(lead_id=lead_id, patient_session_id=ps_id, event_type="consented")
    emit_event(lead_id=lead_id, patient_session_id=ps_id, event_type="patient_created")
    audit(patient_id, "patient_created_from_lead", lead_id)
    return jsonify({"token": token, "patient_session_id": ps_id, "patient_id": patient_id})

@app.post("/api/auth/login")
def login():
    body = request.get_json(force=True)
    row = DB.execute("SELECT * FROM staff_users WHERE name=?", (body.get("name"),)).fetchone()
    if row and check_password_hash(row["password_hash"], body.get("password", "")):
        token = secrets.token_urlsafe(24)
        SESSIONS[token] = {"type": "staff", "id": row["id"], "role": row["role"]}
        return jsonify({"token": token, "role": row["role"]})
    prow = DB.execute("SELECT * FROM patients WHERE email=?", (body.get("email"),)).fetchone()
    if prow and check_password_hash(prow["password_hash"], body.get("password", "")):
        ps = DB.execute("SELECT id FROM patient_sessions WHERE patient_id=? ORDER BY created_at DESC LIMIT 1",
                         (prow["id"],)).fetchone()
        token = secrets.token_urlsafe(24)
        SESSIONS[token] = {"type": "patient", "id": prow["id"], "role": "patient",
                            "patient_session_id": ps["id"] if ps else None}
        return jsonify({"token": token, "role": "patient", "patient_session_id": ps["id"] if ps else None})
    return jsonify({"error": "invalid credentials"}), 401

# Patient chat, risk gating, memory, escalation

EDU_CITATIONS = {
    "period": ("Irregular cycles are common and usually not urgent on their own.", "ACOG patient FAQ, cycle irregularity"),
    "spotting": ("Light spotting between cycles has many benign causes but is worth mentioning to a clinician.", "NHS women's health guidance"),
}

def patient_reply(ps_id, text_redacted, risk):
    if risk["risk_level"] in ("high", "medium"):
        return ("I want to make sure the right person sees this rather than me guessing. "
                "I've prepared everything to send to the clinic — you can review and send it below. "
                "This isn't a diagnosis or a delay tactic, it's what keeps this safe."), None
    low = text_redacted.lower()
    for k, (fact, src) in EDU_CITATIONS.items():
        if k in low:
            return (f"{fact} I'm not able to diagnose or suggest treatment, but a clinician can look into it properly."), src
    return ("Thanks for sharing that. I'm keeping track of it in your profile. "
            "I can give general info, but for anything specific to you, a clinician should weigh in."), None

@app.post("/api/patient/<ps_id>/message")
@require_role("patient")
def patient_message(ps_id):
    if g.session.get("patient_session_id") != ps_id:
        audit(g.session["id"], "unauthorized_cross_patient_access_attempt", ps_id)
        return jsonify({"error": "forbidden"}), 403

    raw = request.get_json(force=True)["message"]
    redacted, _ = redact(raw)  # redacted text that goes to the LLM
    risk = assess_risk(redacted)

    msg_id = new_id()
    DB.execute(
        "INSERT INTO messages (id, patient_session_id, sender, content_redacted, risk_level, risk_reason, "
        "confidence, risk_provenance, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (msg_id, ps_id, "patient", redacted, risk["risk_level"], risk["risk_reason"],
         risk["confidence"], risk["risk_provenance"], now_iso())
    )
    DB.commit()

    facts = extract_facts(msg_id, redacted)
    merge_into_profile(DB, ps_id, facts)

    reply_text, citation = patient_reply(ps_id, redacted, risk)
    DB.execute(
        "INSERT INTO messages (id, patient_session_id, sender, content_redacted, created_at) VALUES (?,?,?,?,?)",
        (new_id(), ps_id, "assistant", reply_text, now_iso())
    )
    DB.commit()
    audit(g.session["id"], "patient_message_processed", ps_id, {"risk_level": risk["risk_level"]})

    return jsonify({
        "reply": reply_text, "citation": citation,
        "risk_level": risk["risk_level"], "risk_reason": risk["risk_reason"],
        "confidence": risk["confidence"], "escalation_required": risk["risk_level"] in ("high", "medium"),
        "triggering_message_id": msg_id,
    })

@app.get("/api/patient/<ps_id>/profile")
@require_role("patient", "staff", "clinician", "nurse")
def get_profile(ps_id):
    if g.session["role"] == "patient" and g.session.get("patient_session_id") != ps_id:
        return jsonify({"error": "forbidden"}), 403
    items = DB.execute("SELECT * FROM memory_items WHERE patient_session_id=?", (ps_id,)).fetchall()
    return jsonify([dict(r) for r in items])

@app.post("/api/patient/<ps_id>/escalate")
@require_role("patient")
def escalate(ps_id):
    if g.session.get("patient_session_id") != ps_id:
        return jsonify({"error": "forbidden"}), 403
    body = request.get_json(force=True)
    trigger_id = body["triggering_message_id"]

    # Handle duplicate requests for the same patient session and triggering message
    existing = DB.execute(
        "SELECT id, triage_summary, status FROM escalations "
        "WHERE patient_session_id=? AND triggering_message_id=? "
        "ORDER BY created_at DESC LIMIT 1",
        (ps_id, trigger_id)
    ).fetchone()

    if existing:
        return jsonify({
            "escalation_id": existing["id"],
            "triage_summary": json.loads(existing["triage_summary"]),
            "expected_response": "12-18 hours",
            "status": existing["status"],
            "already_sent": True
        })

    profile = [dict(r) for r in DB.execute("SELECT * FROM memory_items WHERE patient_session_id=?", (ps_id,)).fetchall()]
    ps = DB.execute("SELECT * FROM patient_sessions WHERE id=?", (ps_id,)).fetchone()
    lead = DB.execute("SELECT * FROM lead_sessions WHERE id=?", (ps["lead_session_id"],)).fetchone()
    trigger = DB.execute("SELECT * FROM messages WHERE id=?", (trigger_id,)).fetchone()

    summary = [f"Chief concern: {i['value']}" for i in profile if i["fact_type"] == "chief_complaint"][:1] \
        + [f"Symptom noted: {i['value']}" for i in profile if i["fact_type"] == "symptom"][:3] \
        + [f"Medication: {i['value']} ({i['status']})" for i in profile if i["fact_type"] == "medication"]
    summary = summary[:5] or ["No structured summary yet — see raw message."]

    attribution = dict(lead) if lead else {}
    esc_id = new_id()
    DB.execute(
        "INSERT INTO escalations (id, patient_session_id, triggering_message_id, triage_summary, "
        "profile_snapshot, attribution_snapshot, status, created_at) VALUES (?,?,?,?,?,?,?,?)",
        (esc_id, ps_id, trigger_id, json.dumps(summary), json.dumps(profile),
         json.dumps(attribution), "pending", now_iso())
    )
    DB.commit()
    emit_event(patient_session_id=ps_id, event_type="escalation_sent")
    audit(g.session["id"], "escalation_created", esc_id)
    return jsonify({"escalation_id": esc_id, "triage_summary": summary,
                     "expected_response": "12-18 hours", "status": "pending"})

# Staff/Clinician dashboard

"""
Ranks leads using recency, channel, identity level, and funnel stage.
High-risk clinical concerns are handled separately and never included in sales scoring.
"""
@app.get("/api/staff/warm-leads")
@require_role("staff", "clinician", "nurse")
def warm_leads():
    leads = DB.execute("SELECT * FROM lead_sessions ORDER BY created_at DESC LIMIT 50").fetchall()
    CHANNEL_WEIGHT = {"staff_referral": 5, "lead_form": 4, "instagram_comment": 3,
                       "tiktok_comment": 3, "facebook_comment": 3, "google_reviews": 3,
                       "website_widget": 2, "instagram_ad_click": 1, "google_ad_click": 1}
    scored = []
    for lead in leads:
        age_hours = (datetime.now(timezone.utc) - datetime.fromisoformat(lead["landing_timestamp"])).total_seconds() / 3600
        recency_score = max(0, 10 - age_hours / 6)
        identity_score = 5 if lead["identity_level"] == "identified" else 1
        channel_score = CHANNEL_WEIGHT.get(lead["source_channel"], 1)
        stage_score = 10 if lead["status"] == "converted" else 3
        score = round(recency_score + identity_score + channel_score + stage_score, 1)
        top_msg = DB.execute(
            "SELECT content_redacted FROM guest_messages WHERE lead_session_id=? AND sender='guest' ORDER BY created_at LIMIT 1",
            (lead["id"],)
        ).fetchone()
        scored.append({
            "lead_id": lead["id"], "channel": lead["source_channel"], "identity_level": lead["identity_level"],
            "status": lead["status"], "score": score,
            "top_concern": top_msg["content_redacted"] if top_msg else lead["context"],
            "contactable": bool(lead["email"] or lead["handle"]),
        })

    # compassion queue is separate and always shown first, never scored for sales
    escalations = DB.execute("SELECT * FROM escalations WHERE status='pending' ORDER BY created_at").fetchall()
    compassion = [{"escalation_id": e["id"], "summary": json.loads(e["triage_summary"]),
                   "created_at": e["created_at"]} for e in escalations]

    scored.sort(key=lambda x: x["score"], reverse=True)
    return jsonify({"compassion_priority_queue": compassion, "warm_leads": scored})

@app.get("/api/staff/funnel-metrics")
@require_role("staff", "clinician", "nurse")
def funnel_metrics():
    rows = DB.execute(
        "SELECT ls.source_channel, fe.event_type, COUNT(*) c FROM funnel_events fe "
        "JOIN lead_sessions ls ON ls.id = fe.lead_session_id GROUP BY ls.source_channel, fe.event_type"
    ).fetchall()
    out = {}
    for r in rows:
        out.setdefault(r["source_channel"], {})[r["event_type"]] = r["c"]
    return jsonify(out)

@app.get("/api/staff/escalation/<esc_id>")
@require_role("staff", "clinician", "nurse")
def get_escalation(esc_id):
    row = DB.execute("SELECT * FROM escalations WHERE id=?", (esc_id,)).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    d = dict(row)
    d["triage_summary"] = json.loads(d["triage_summary"])
    d["profile_snapshot"] = json.loads(d["profile_snapshot"])
    d["attribution_snapshot"] = json.loads(d["attribution_snapshot"])
    return jsonify(d)

@app.post("/api/staff/escalation/<esc_id>/respond")
@require_role("clinician", "nurse")
def respond_escalation(esc_id):
    body = request.get_json(force=True)
    DB.execute("UPDATE escalations SET status='responded', clinician_response=? WHERE id=?",
               (body["response"], esc_id))
    DB.commit()
    audit(g.session["id"], "escalation_responded", esc_id)
    return jsonify({"status": "responded"})

# seed one of each staff role for the demo
if __name__ == "__main__":
    for name, role in [("nurse_amy", "nurse"), ("dr_lim", "clinician"), ("frontdesk_wan", "staff")]:
        if not DB.execute("SELECT 1 FROM staff_users WHERE name=?", (name,)).fetchone():
            DB.execute("INSERT INTO staff_users (id, name, role, password_hash) VALUES (?,?,?,?)",
                       (new_id(), name, role, generate_password_hash("demo1234")))
    DB.commit()
    app.run(debug=True, port=5000)