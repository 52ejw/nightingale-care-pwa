"""
Extracts key facts from patient messages and updates existing Memory items
when information is corrected. Each fact records which message it came from.
"""
import re
import uuid
from datetime import datetime, timezone

STOP_WORDS = [r"stopped", r"not taking anymore", r"quit", r"discontinued", r"no longer taking", r"not taking anymore", r"no longer", r"discontinuing"]
MED_PATTERN = re.compile(r"\b(?:i take|i am taking|i'm taking|taking|on)\s+([A-Za-z][\w-]{2,20})\b", re.IGNORECASE)
ALLERGY_PATTERN = re.compile(r"allergic to\s+([A-Za-z][\w-]{2,20})", re.IGNORECASE)
SYMPTOM_PATTERN = re.compile(
    r"\b(pain|ache|bleeding|fever|nausea|dizziness|cramping|discharge|swelling)\b", re.IGNORECASE
)
TIMELINE_PATTERN = re.compile(
    r"\b(?:for|since)\s+(?:\d+\s+(?:day|week|month|hour)s?|yesterday|last night|last week|this morning)\b",
    re.IGNORECASE,
)

def extract_facts(message_id: str, text: str) -> list[dict]:
    """Returns possible facts; the mutation logic decides how they are added or updated in memory."""
    now = datetime.now(timezone.utc).isoformat()
    facts = []

    for m in MED_PATTERN.finditer(text):
        med = m.group(1).strip(".,!?").capitalize()
        stopped = any(re.search(sw, text, re.IGNORECASE) for sw in STOP_WORDS)
        facts.append({
            "fact_type": "medication", "value": med,
            "status": "stopped" if stopped else "active",
            "provenance_pointer": message_id, "updated_at": now,
        })

    for m in ALLERGY_PATTERN.finditer(text):
        facts.append({
            "fact_type": "allergy", "value": m.group(1).strip(".,!?").capitalize(),
            "status": "active", "provenance_pointer": message_id, "updated_at": now,
        })

        timeline_match = TIMELINE_PATTERN.search(text)
        for m in SYMPTOM_PATTERN.finditer(text):
            symptom = m.group(1).lower()
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
        Mutation, not duplication: a new medication fact with the same value updates the
        existing row's status + provenance instead of creating a second row.
        """
    for fact in new_facts:
        existing = db.execute(
            "SELECT id FROM memory_items WHERE patient_session_id=? AND fact_type=? AND lower(value)=lower(?)",
            (patient_session_id, fact["fact_type"], fact["value"]),
        ).fetchone()
        if existing and fact["fact_type"] in ("medication", "allergy"):
            db.execute(
                "UPDATE memory_items SET status=?, provenance_pointer=?, updated_at=? WHERE id=?",
                (fact["status"], fact["provenance_pointer"], fact["updated_at"], existing["id"]),
            )
        else:
            db.execute(
                "INSERT INTO memory_items (id, patient_session_id, fact_type, value, status, provenance_pointer, updated_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), patient_session_id, fact["fact_type"], fact["value"],
                 fact["status"], fact["provenance_pointer"], fact["updated_at"]),
            )
    db.commit()