"""
Extracts key facts from patient messages and updates existing Memory items
when information is corrected. Each fact records which message it came from.
"""
import re
import uuid
from datetime import datetime, timezone

# Phrases that suggest someone stopped taking a medication
STOP_WORDS = [r"stopped", r"not taking anymore", r"quit", r"discontinued", r"no longer taking", r"not taking anymore", r"no longer", r"discontinuing"]
# Matches phrases like "I take X" or "I'm taking X" to find medication names
MED_PATTERN = re.compile(r"\b(?:i take|i am taking|i'm taking|taking|on)\s+([A-Za-z][\w-]{2,20})\b", re.IGNORECASE)
# Matches phrases like "allergic to X" to find allergies
ALLERGY_PATTERN = re.compile(r"allergic to\s+([A-Za-z][\w-]{2,20})", re.IGNORECASE)
# Matches common symptom words (pain, fever, nausea, etc.)
SYMPTOM_PATTERN = re.compile(
    r"\b(pain|ache|bleeding|fever|nausea|dizziness|cramping|discharge|swelling)\b", re.IGNORECASE
)
# Matches time phrases like "for 3 days" or "since last night", to attach a timeframe to a symptom
TIMELINE_PATTERN = re.compile(
    r"\b(?:for|since)\s+(?:\d+\s+(?:day|week|month|hour)s?|yesterday|last night|last week|this morning)\b",
    re.IGNORECASE,
)

def extract_facts(message_id: str, text: str) -> list[dict]:
    """Returns possible facts; the mutation logic decides how they are added or updated in memory."""
    now = datetime.now(timezone.utc).isoformat()
    facts = []

    # Look for any medications mentioned in the message
    for m in MED_PATTERN.finditer(text):
        med = m.group(1).strip(".,!?").capitalize()
        # Check if the message also says they stopped taking it
        stopped = any(re.search(sw, text, re.IGNORECASE) for sw in STOP_WORDS)
        facts.append({
            "fact_type": "medication", "value": med,
            "status": "stopped" if stopped else "active",
            "provenance_pointer": message_id, "updated_at": now,
        })

    # Look for any allergies mentioned in the message
    for m in ALLERGY_PATTERN.finditer(text):
        facts.append({
            "fact_type": "allergy", "value": m.group(1).strip(".,!?").capitalize(),
            "status": "active", "provenance_pointer": message_id, "updated_at": now,
        })

    # Look for a timeframe first (e.g. "for 3 days"), so it can be attached to any symptom found below
    timeline_match = TIMELINE_PATTERN.search(text)
    for m in SYMPTOM_PATTERN.finditer(text):
        symptom = m.group(1).lower()
        # If we found a timeframe, tack it onto the symptom (e.g. "pain (for 3 days)")
        value = f"{symptom} ({timeline_match.group(0).strip()})" if timeline_match else symptom
        facts.append({
            "fact_type": "symptom", "value": value,
            "status": "active", "provenance_pointer": message_id, "updated_at": now,
        })

    # First substantive sentence, if nothing more specific was extracted, becomes chief complaint
    if not facts and len(text.strip()) > 4:
        facts.append({
            "fact_type": "chief_complaint", "value": text.strip()[:140],
            "status": "active", "provenance_pointer": message_id, "updated_at": now,
        })

    return facts

def merge_into_profile(db, patient_session_id: str, new_facts: list[dict]):
    """
        Append-only for medications/allergies: a correction never overwrites
        the row it corrects. Instead the old row is marked 'superseded' and
        a new row is inserted pointing back at it, so both the original
        provenance and the correction's provenance stay resolvable.
        """
    for fact in new_facts:
        # Check if we already have this exact fact stored for this patient
        existing = db.execute(
            "SELECT id FROM memory_items WHERE patient_session_id=? AND fact_type=? AND lower(value)=lower(?) AND status != 'superseded'",
            (patient_session_id, fact["fact_type"], fact["value"]),
        ).fetchone()
        if existing and fact["fact_type"] in ("medication", "allergy"):
            if existing["id"]:
                # Don't insert a no-op supersede if nothing actually changed
                pass
            db.execute(
                "UPDATE memory_items SET status='superseded' WHERE id=?",
                (existing["id"],),
            )
            db.execute(
                "INSERT INTO memory_items (id, patient_session_id, fact_type, value, status, "
                "provenance_pointer, updated_at, supersedes) VALUES (?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), patient_session_id, fact["fact_type"], fact["value"],
                 fact["status"], fact["provenance_pointer"], fact["updated_at"], existing["id"]),
            )
        else:
            # Otherwise, this is a new fact — insert it as a fresh row
            db.execute(
                "INSERT INTO memory_items (id, patient_session_id, fact_type, value, status, provenance_pointer, updated_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), patient_session_id, fact["fact_type"], fact["value"],
                 fact["status"], fact["provenance_pointer"], fact["updated_at"]),
            )
    db.commit()