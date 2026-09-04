"""
Nightingale backend. A simple Flask app that uses 
bearer tokens for login and checks user roles and access on the server.
Audit logs store only hashes and metadata, never raw patient messages.
"""

from dotenv import load_dotenv
load_dotenv()

import hashlib
import json
import os
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

# Optional LLM client for low-risk conversational responses
try:
    from anthropic import Anthropic
    _ANTHROPIC_CLIENT = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"]) if os.environ.get("ANTHROPIC_API_KEY") else None
except Exception:
    _ANTHROPIC_CLIENT = None

def call_llm(system_prompt: str, user_text: str, max_tokens: int = 300):
    """LLM call for low-risk conversational replies only — never used for
    risk determination, which stays deterministic in risk_gating.py.
    Returns None on missing key, timeout, or any API error, so callers
    fall back to a safe canned response. This IS the documented failure
    mode for 'LLM times out' — the user always gets a safe reply, never
    a hang or a raw error."""
    if not _ANTHROPIC_CLIENT:
        return None
    try:
        resp = _ANTHROPIC_CLIENT.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_text}],
            timeout=8.0,
        )
        text = "".join(b.text for b in resp.content if b.type == "text").strip()
        return text or None
    except Exception:
        return None

# Configures the Flask app, database, guest retention, and session storage
app = Flask(__name__, static_folder="static", static_url_path="")
DB = init_db()

GUEST_TTL_DAYS = 30  

# Removes expired guest data after the 30-day retention period
def purge_expired_guest_data():
    cutoff = datetime.now() - timedelta(days=GUEST_TTL_DAYS)
    cutoff_iso = cutoff.isoformat()

    DB.execute(
        "DELETE FROM guest_messages WHERE lead_session_id IN "
        "(SELECT id FROM lead_sessions WHERE created_at < ? AND status != 'converted')",
        (cutoff_iso,)
    )

    DB.execute(
        "DELETE FROM value_events WHERE lead_session_id IN "
        "(SELECT id FROM lead_sessions WHERE created_at < ? AND status != 'converted')",
        (cutoff_iso,)
    )

    DB.execute(
        "DELETE FROM lead_sessions WHERE created_at < ? AND status != 'converted'",
        (cutoff_iso,)
    )

    DB.commit()

purge_expired_guest_data()

# Stores active authentication sessions in memory
SESSIONS: dict[str, dict] = {}     
# Tracks guest messages for basic rate limiting     
GUEST_RATE_LIMIT: dict[str, list] = {}                     

# Common helpers for timestamps, IDs, audit logs, and events
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

# Restricts an endpoint to users with an allowed role
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

# Limits how many guest messages can be sent within one minute
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

# Starts guest sessions and records their acquisition channel and attribution
@app.post("/api/lead/start")
def lead_start():
    purge_expired_guest_data()
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
# Creates a referral link that staff can send to a patient
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
# Converts a staff referral token into a new guest session
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
        "INSERT INTO lead_sessions (id, clinic_id, source_channel, identity_level, context, handle, landing_timestamp, created_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (lead_id, "sunway_whf", kw["channel"], kw["identity_level"], kw["context"], kw.get("handle"), now_iso(), now_iso())
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
    resp = lead_start_internal(
        channel=platform,
        identity_level="anonymous",
        context=body.get("post_topic", "your comment"),
        handle=body.get("handle"),
    )
    return jsonify({"dm_sent": True, "portal_link": f"/?lead={resp['lead_session_id']}",
                     "opening": resp["greeting"]})

# Provides safe guest education and controls when conversational AI can respond
VALUE_KB = {
    "egg freezing": "Egg freezing (oocyte cryopreservation) involves ovarian stimulation, egg retrieval, then vitrification — most clinics quote a 2-3 week process per cycle.",
    "ivf": "IVF success rates vary strongly by age and clinic — ask for the clinic's own live-birth-per-cycle rate by age band, not just the national average.",
    "fertility": "A basic fertility workup usually starts with hormone bloodwork and a semen analysis where relevant, before anything more invasive.",
}

GUEST_SYSTEM_PROMPT = (
    "You are Nightingale, a fertility/women's health clinic's AI assistant talking to an "
    "anonymous website visitor who has not signed up yet. You are strictly non-diagnostic: "
    "never say 'you have X', never suggest medication changes or treatment plans beyond "
    "general info + 'consult a clinician', never give false reassurance on symptoms that "
    "sound concerning. Be warm and brief (2-4 sentences). Do not ask for contact info."
)

# Generates a safe guest response using the LLM or a canned fallback
def guest_reply(lead_id, text_redacted):
    low = text_redacted.lower()
    if "real doctor" in low or "are you a bot" in low or "are you human" in low:
        return ("I'm Nightingale, an AI assistant built for this clinic — I'm not a doctor and I don't diagnose. "
                "I can answer general questions and pass anything clinical to a real nurse or clinician, usually within 12-18 hours. "
                "You're chatting with software right now, and I'll always tell you when a human takes over."), "trust_response"

    llm_reply = call_llm(GUEST_SYSTEM_PROMPT, text_redacted)
    if llm_reply:
        return llm_reply, "education"

    for topic, fact in VALUE_KB.items():
        if topic in low:
            return (f"{fact} I can't say what's right for your specific situation, but a clinician can once you're ready to share more."), "education"
    return ("Happy to help — I can share general info on services, hours, and what to expect, "
            "all without needing an account yet. What would you like to know?"), "education"

@app.get("/api/lead/<lead_id>")
def get_lead(lead_id):
    row = DB.execute(
        "SELECT id, clinic_id, source_channel, campaign_id, creative, "
        "identity_level, context, status, handle, landing_timestamp, created_at "
        "FROM lead_sessions WHERE id=?",
        (lead_id,),
    ).fetchone()

    if not row:
        return jsonify({"error": "Lead session not found"}), 404

    return jsonify({
        "lead_session_id": row["id"],
        "clinic_id": row["clinic_id"],
        "source_channel": row["source_channel"],
        "campaign_id": row["campaign_id"],
        "creative": row["creative"],
        "identity_level": row["identity_level"],
        "context": row["context"],
        "handle": row["handle"],
        "status": row["status"],
        "landing_timestamp": row["landing_timestamp"],
        "created_at": row["created_at"],
    })
@app.post("/api/lead/<lead_id>/message")
def guest_message(lead_id):
    lead = DB.execute(
        "SELECT * FROM lead_sessions WHERE id=?",
        (lead_id,)
    ).fetchone()

    if not lead:
        return jsonify({"error": "not found"}), 404

    if rate_limited(lead_id):
        return jsonify({
            "error": "rate_limited",
            "message": "Too many messages — please slow down a moment."
        }), 429

    raw = request.get_json(force=True)["message"]
    risk = assess_risk(raw)
    redacted, phi_found = redact(raw)

    # Create the message ID first so any escalation points to the exact triggering message 
    msg_id = new_id()

    enc = encrypt(raw) if phi_found else None

    DB.execute(
        "INSERT INTO guest_messages "
        "(id, lead_session_id, sender, content_redacted, phi_detected, encrypted_raw, "
        "risk_level, risk_reason, confidence, risk_provenance, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            msg_id, lead_id, "guest", redacted, int(phi_found), enc,
            risk["risk_level"], risk["risk_reason"], risk["confidence"], risk["risk_provenance"],
            now_iso()
        )
    )

    DB.commit()

    audit(
        None,
        "guest_message_received",
        lead_id,
        {"phi_detected": phi_found}
    )

    escalation_id = None  # stays None unless the block below sets it

    if risk["risk_level"] in ("high", "medium"):
        reply = (
            "I want to make sure the right person sees this rather than me guessing. "
            "Because you've mentioned something that may need clinical attention, "
            "I'm not going to give you a generic answer. "
            "I've flagged this for the clinic so a nurse or clinician can review it."
        )
        event_type = "clinical_escalation"

        # Sends high- and medium-risk guest messages to the clinical priority queue
        triage_summary = {
            "risk_level": risk["risk_level"],
            "risk_reason": risk["risk_reason"],
            "confidence": risk["confidence"],
            "risk_provenance": risk["risk_provenance"],
            "triggering_message_id": msg_id,
        }

        attribution_snapshot = dict(lead)

        escalation_id = new_id()

        DB.execute(
            "INSERT INTO escalations "
            "(id, patient_session_id, triggering_message_id, triage_summary, "
            "profile_snapshot, attribution_snapshot, status, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (
                escalation_id,
                None,
                msg_id,
                json.dumps(triage_summary),
                json.dumps([]),
                json.dumps(attribution_snapshot),
                "pending",
                now_iso()
            )
        )

        DB.commit()

        emit_event(
            lead_id=lead_id,
            event_type="escalation_sent",
            meta={
                "escalation_id": escalation_id,
                "risk_level": risk["risk_level"]
            }
        )

        audit(
            None,
            "guest_escalation_created",
            escalation_id,
            {"risk_level": risk["risk_level"]}
        )

    else:
        reply, event_type = guest_reply(lead_id, redacted)

    # Store the assistant response.
    DB.execute(
        "INSERT INTO guest_messages "
        "(id, lead_session_id, sender, content_redacted, created_at) "
        "VALUES (?,?,?,?,?)",
        (
            new_id(),
            lead_id,
            "assistant",
            reply,
            now_iso()
        )
    )

    DB.execute(
        "INSERT INTO value_events "
        "(id, lead_session_id, event_type, content, created_at) "
        "VALUES (?,?,?,?,?)",
        (
            new_id(),
            lead_id,
            event_type,
            reply,
            now_iso()
        )
    )

    DB.commit()

    emit_event(
        lead_id=lead_id,
        event_type="value_event",
        meta={"kind": event_type}
    )

    return jsonify({
    "reply": reply,
    "value_event": event_type,
    "trust_prompt_available": True,
    "risk_level": risk["risk_level"],
    "escalation_required": risk["risk_level"] in ("high", "medium"),
    "escalation_id": escalation_id,
})
"""
Creates a short, personalised note based on what the user actually said.
Limited to 240 characters as required by the brief.
"""
@app.get("/api/lead/<lead_id>/personal-note")
# Creates a personalised value message from the guest's latest input
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
Earned email: generates a personalized summary + 6 forgotten questions from
the guest's own session, in exchange for an email — before full signup.
This send is transactional and independent from marketing consent.
"""
@app.post("/api/lead/<lead_id>/summary-email")
def summary_email(lead_id):
    lead = DB.execute("SELECT * FROM lead_sessions WHERE id=?", (lead_id,)).fetchone()
    if not lead:
        return jsonify({"error": "not found"}), 404

    body = request.get_json(force=True)
    email = body.get("email")
    if not email:
        return jsonify({"error": "email is required"}), 400

    msgs = DB.execute(
        "SELECT content_redacted FROM guest_messages WHERE lead_session_id=? AND sender='guest' ORDER BY created_at",
        (lead_id,)
    ).fetchall()
    topic = msgs[-1]["content_redacted"][:60] if msgs else lead["context"]

    summary, _ = redact(f"Quick recap of what you shared with us about {topic.lower()}.")
    questions = [
        "What are my realistic success rates at my age, specifically?",
        "What tests or bloodwork should happen before we start?",
        "What are the risks and side effects I should watch for?",
        "How many cycles do most people like me typically need?",
        "What does this cost, and what's covered vs out-of-pocket?",
        "What happens if this first approach doesn't work?",
    ]

    DB.execute(
        "INSERT INTO value_events (id, lead_session_id, event_type, content, created_at) VALUES (?,?,?,?,?)",
        (new_id(), lead_id, "summary_email", summary, now_iso())
    )
    DB.commit()
    emit_event(lead_id=lead_id, event_type="value_event", meta={"kind": "summary_email"})
    audit(None, "summary_email_sent", lead_id, {"transactional": True})

    # Simulates the transactional email for the demo
    return jsonify({
        "sent_to": email, "summary": summary, "questions": questions,
        "transactional": True,
        "marketing_consent_required_for_further_emails": True,
    })

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

# Converts a verified guest session into an authenticated patient session

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

    emit_event(lead_id=lead_id, event_type="auth_started")

    if not body.get("healthcare_consent", False):
        return jsonify({
            "error": "Healthcare information sharing consent is required."
        }), 400

    emit_event(lead_id=lead_id, event_type="consented")
    lead = DB.execute("SELECT * FROM lead_sessions WHERE id=?", (lead_id,)).fetchone()
    if not lead:
        return jsonify({"error": "lead not found"}), 404

    patient = DB.execute("SELECT * FROM patients WHERE email=?", (email,)).fetchone()
    if not patient:
        patient_id = new_id()  # immutable internal PK; email/phone can change later without breaking this
        DB.execute(
            "INSERT INTO patients (id, email, phone, password_hash, email_verified, phone_verified, "
            "verification_code, marketing_consent, marketing_consent_ts, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (patient_id, email, phone, generate_password_hash(body["password"]),
            0, 0, secrets.token_hex(3).upper(),
            int(body.get("marketing_consent", False)),
            now_iso() if body.get("marketing_consent") else None,
            now_iso())
        )
    else:
        patient_id = patient["id"]
    DB.commit()

    verification = DB.execute(
        "SELECT verification_code FROM patients WHERE id=?",
        (patient_id,)
    ).fetchone()

    return jsonify({
        "verification_required": True,
        "email": email,
        "lead_session_id": lead_id,
        "verification_code": verification["verification_code"],
    })

@app.post("/api/auth/verify")
def verify_patient():
    body = request.get_json(force=True)
    email = body.get("email")
    code = body.get("code")
    lead_id = body.get("lead_session_id")

    patient = DB.execute(
        "SELECT * FROM patients WHERE email=? AND verification_code=?",
        (email, code)
    ).fetchone()

    if not patient:
        return jsonify({"error": "Invalid verification code."}), 400

    if not lead_id:
        return jsonify({"error": "lead_session_id is required."}), 400

    lead = DB.execute(
        "SELECT * FROM lead_sessions WHERE id=?",
        (lead_id,)
    ).fetchone()

    if not lead:
        return jsonify({"error": "lead not found"}), 404

    # Mark contact details as verified.
    DB.execute(
        "UPDATE patients SET email_verified=1, phone_verified=1, verification_code=NULL WHERE id=?",
        (patient["id"],)
    )

    # Create the authenticated patient session.
    ps_id = new_id()
    DB.execute(
        "INSERT INTO patient_sessions "
        "(id, patient_id, lead_session_id, consent_share_ts, created_at) "
        "VALUES (?,?,?,?,?)",
        (
            ps_id,
            patient["id"],
            lead_id,
            now_iso(),
            now_iso(),
        )
    )

    # Convert the lead.
    DB.execute(
        "UPDATE lead_sessions SET status='converted' WHERE id=?",
        (lead_id,)
    )

    # Migrate permitted guest context into the authenticated profile.
    guest_msgs = DB.execute(
        "SELECT * FROM guest_messages "
        "WHERE lead_session_id=? AND sender='guest' "
        "ORDER BY created_at",
        (lead_id,)
    ).fetchall()

    for gm in guest_msgs:
        facts = extract_facts(gm["id"], gm["content_redacted"])
        merge_into_profile(DB, ps_id, facts)

    DB.commit()

    # Create authenticated session token.
    token = secrets.token_urlsafe(24)
    SESSIONS[token] = {
        "type": "patient",
        "id": patient["id"],
        "role": "patient",
        "patient_session_id": ps_id,
    }

    emit_event(
        lead_id=lead_id,
        patient_session_id=ps_id,
        event_type="patient_created",
    )

    audit(
        patient["id"],
        "patient_created_from_lead",
        lead_id,
    )

    return jsonify({
        "verified": True,
        "token": token,
        "patient_session_id": ps_id,
        "patient_id": patient["id"],
    })

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

# Handles authenticated patient messages, memory updates, risk gating, and escalation

EDU_CITATIONS = {
    "period": ("Irregular cycles are common and usually not urgent on their own.", "ACOG patient FAQ, cycle irregularity"),
    "spotting": ("Light spotting between cycles has many benign causes but is worth mentioning to a clinician.", "NHS women's health guidance"),
}

PATIENT_SYSTEM_PROMPT = (
    "You are Nightingale, an AI assistant inside a fertility/women's health clinic's authenticated "
    "patient portal. You are strictly non-diagnostic: never say 'you have X', never suggest "
    "medication changes or treatment plans beyond general info + 'consult a clinician', never give "
    "false reassurance on symptoms that sound concerning. Be warm and brief (2-4 sentences)."
)

PATIENT_SYSTEM_PROMPT = (
    "You are Nightingale, an AI assistant inside a fertility/women's health clinic's authenticated "
    "patient portal. You are strictly non-diagnostic: never say 'you have X', never suggest "
    "medication changes or treatment plans beyond general info + 'consult a clinician', never give "
    "false reassurance on symptoms that sound concerning. Be warm and brief (2-4 sentences)."
)

def patient_reply(ps_id, text_redacted, risk):
    if risk["risk_level"] in ("high", "medium"):
        return ("I want to make sure the right person sees this rather than me guessing. "
                "I've prepared everything to send to the clinic — you can review and send it below. "
                "This isn't a diagnosis or a delay tactic, it's what keeps this safe."), None

    low = text_redacted.lower()
    for k, (fact, src) in EDU_CITATIONS.items():
        if k in low:
            llm_reply = call_llm(PATIENT_SYSTEM_PROMPT, text_redacted)
            return (llm_reply or f"{fact} I'm not able to diagnose or suggest treatment, but a clinician can look into it properly."), src

    llm_reply = call_llm(PATIENT_SYSTEM_PROMPT, text_redacted)
    if llm_reply:
        return llm_reply, None
    return ("Thanks for sharing that. I'm keeping track of it in your profile. "
            "I can give general info, but for anything specific to you, a clinician should weigh in."), None

def create_escalation(ps_id, triggering_message_id, risk):
    profile_rows = DB.execute(
        "SELECT * FROM memory_items WHERE patient_session_id=?",
        (ps_id,)
    ).fetchall()

    profile_snapshot = [dict(row) for row in profile_rows]

    session = DB.execute(
        "SELECT * FROM patient_sessions WHERE id=?",
        (ps_id,)
    ).fetchone()

    lead = None
    if session and session["lead_session_id"]:
        lead = DB.execute(
            "SELECT * FROM lead_sessions WHERE id=?",
            (session["lead_session_id"],)
        ).fetchone()

    attribution_snapshot = dict(lead) if lead else {}

    triage_summary = {
        "risk_level": risk["risk_level"],
        "risk_reason": risk["risk_reason"],
        "confidence": risk["confidence"],
        "triggering_message_id": triggering_message_id,
    }

    DB.execute(
        "INSERT INTO escalations "
        "(id, patient_session_id, triggering_message_id, triage_summary, "
        "profile_snapshot, attribution_snapshot, status, created_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (
            new_id(),
            ps_id,
            triggering_message_id,
            json.dumps(triage_summary),
            json.dumps(profile_snapshot),
            json.dumps(attribution_snapshot),
            "pending",
            now_iso(),
        )
    )
    DB.commit()

@app.post("/api/patient/<ps_id>/message")
@require_role("patient")
def patient_message(ps_id):
    if g.session.get("patient_session_id") != ps_id:
        audit(g.session["id"], "unauthorized_cross_patient_access_attempt", ps_id)
        return jsonify({"error": "forbidden"}), 403

    raw = request.get_json(force=True)["message"]
    risk = assess_risk(raw)
    redacted, _ = redact(raw)  # Redacted text used only for storage and response generation

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
    if risk["risk_level"] in ("high", "medium"):
        create_escalation(
            ps_id=ps_id,
            triggering_message_id=msg_id,
            risk=risk
        )
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
# Returns the patient's saved profile information
def get_profile(ps_id):
    if g.session["role"] == "patient" and g.session.get("patient_session_id") != ps_id:
        return jsonify({"error": "forbidden"}), 403
    items = DB.execute(
        "SELECT * FROM memory_items WHERE patient_session_id=? AND status != 'superseded'",
        (ps_id,)
    ).fetchall()
    return jsonify([dict(r) for r in items])

@app.get("/api/patient/<ps_id>/messages")
@require_role("patient", "staff", "clinician", "nurse")
# Returns the message thread so a returning session or a poll can hydrate it
def get_messages(ps_id):
    if g.session["role"] == "patient" and g.session.get("patient_session_id") != ps_id:
        return jsonify({"error": "forbidden"}), 403
    rows = DB.execute(
        "SELECT id, sender, content_redacted, created_at FROM messages "
        "WHERE patient_session_id=? ORDER BY created_at",
        (ps_id,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.post("/api/patient/<ps_id>/escalate")
@require_role("patient")
def escalate(ps_id):
    if g.session.get("patient_session_id") != ps_id:
        return jsonify({"error": "forbidden"}), 403
    body = request.get_json(force=True)
    trigger_id = body["triggering_message_id"]

    # Prevents the same message from being escalated more than once
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
    emit_event(
    lead_id=ps["lead_session_id"],
    patient_session_id=ps_id,
    event_type="escalation_sent",
    )
    audit(g.session["id"], "escalation_created", esc_id)
    return jsonify({"escalation_id": esc_id, "triage_summary": summary,
                     "expected_response": "12-18 hours", "status": "pending"})

# Staff dashboard for clinical escalations and lead follow-up

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
        # Guest messages stay hidden from staff until consent; staff only see the topic.
        top_concern = lead["context"]
        if lead["status"] == "converted":
            top_msg = DB.execute(
                "SELECT content_redacted FROM guest_messages WHERE lead_session_id=? AND sender='guest' ORDER BY created_at LIMIT 1",
                (lead["id"],)
            ).fetchone()
            if top_msg:
                top_concern = top_msg["content_redacted"]

        scored.append({
            "lead_id": lead["id"], "channel": lead["source_channel"], "identity_level": lead["identity_level"],
            "status": lead["status"], "score": score,
            "top_concern": top_concern,
            "contactable": bool(lead["email"] or lead["handle"]),
        })

    # Keeps clinical concerns separate from sales-ranked leads
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
    d["is_guest"] = d["patient_session_id"] is None

    # Guest escalations point at guest_messages; patient escalations point at messages.
    table = "guest_messages" if d["is_guest"] else "messages"
    msg = DB.execute(
        f"SELECT content_redacted, created_at FROM {table} WHERE id=?",
        (d["triggering_message_id"],)
    ).fetchone()
    d["triggering_message"] = dict(msg) if msg else None

    return jsonify(d)

@app.get("/api/staff/guest-message/<msg_id>/reveal")
@require_role("clinician", "nurse")
# Allows authorised clinical staff to reveal encrypted guest PHI after consent
def reveal_guest_phi(msg_id):
    row = DB.execute(
        "SELECT gm.*, ls.status AS lead_status FROM guest_messages gm "
        "JOIN lead_sessions ls ON ls.id = gm.lead_session_id WHERE gm.id=?",
        (msg_id,)
    ).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    if not row["encrypted_raw"]:
        return jsonify({"error": "no PHI recorded for this message"}), 404
    if row["lead_status"] != "converted":
        return jsonify({"error": "cannot reveal PHI before the guest has consented (lead not converted)"}), 403
    raw = decrypt(row["encrypted_raw"])
    audit(g.session["id"], "guest_phi_revealed", msg_id)
    return jsonify({"raw_message": raw})

@app.post("/api/staff/escalation/<esc_id>/respond")
@require_role("clinician", "nurse")
# Records the clinician's response and closes the pending escalation
def respond_escalation(esc_id):
    body = request.get_json(force=True)

    row = DB.execute(
        "SELECT id, patient_session_id FROM escalations WHERE id=?",
        (esc_id,)
    ).fetchone()

    if not row:
        return jsonify({"error": "escalation not found"}), 404

    DB.execute(
        "UPDATE escalations SET status='responded', clinician_response=? WHERE id=?",
        (body["response"], esc_id)
    )

    # Puts the reply into the patient's own thread — an escalation response
    # that only lives on the escalations row is invisible to the patient.
    if row["patient_session_id"]:
        DB.execute(
            "INSERT INTO messages (id, patient_session_id, sender, content_redacted, created_at) "
            "VALUES (?,?,?,?,?)",
            (new_id(), row["patient_session_id"], "clinician", body["response"], now_iso())
        )
    DB.commit()

    audit(g.session["id"], "escalation_responded", esc_id)

    return jsonify({"status": "responded"})

# Creates one demo account for each staff role when the app starts
if __name__ == "__main__":
    for name, role in [("nurse_amy", "nurse"), ("dr_lim", "clinician"), ("frontdesk_wan", "staff")]:
        if not DB.execute("SELECT 1 FROM staff_users WHERE name=?", (name,)).fetchone():
            DB.execute("INSERT INTO staff_users (id, name, role, password_hash) VALUES (?,?,?,?)",
                       (new_id(), name, role, generate_password_hash("demo1234")))
    DB.commit()
    app.run(debug=True, port=5000)