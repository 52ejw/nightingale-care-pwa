# Nightingale — 48hr build

## Run it

pip install -r requirements.txt
python app.py # serves the app + API on http://localhost:5000

## Test it

pytest tests/test_nightingale.py -v

## Where redaction happens

`redaction.py::redact()` — called on every guest message (app.py `guest_message`) and
every patient message (`patient_message`) BEFORE the text is used to compose a reply
or written anywhere. Names/IC/phone/email are stripped. Anything a guest volunteers
before consent is additionally encrypted (`redaction.py::encrypt`) and withheld from
staff views until the lead converts.

## RBAC enforcement

`app.py::require_role()` checks a server-side session map on every protected route —
never trusts a client-supplied role. Patient routes additionally check
`g.session["patient_session_id"] == ps_id` so Patient A can never reach Patient B's
data, even with a valid token. See `test_access_control.py`.

## Guest data retention

Guest-only data (no PHI, no auth) is kept `GUEST_TTL_DAYS = 30` for abandonment
analytics — i.e. "why did they never sign up" (channel, timing, whether a value_event
fired) — because that's the one thing worth learning from someone who left. Anything
they typed that contains PHI is destroyed on the same clock rather than retained
"just in case." A scheduled job (not wired up in the 48hr slice — noted as a cut) would
run this purge nightly.

## Failure modes (documented, not all fully implemented)

- LLM/response generation timeout → patient sees "I couldn't process that — nothing was
  lost, try again or press Send to Nurse/Clinic directly." Risk gating runs BEFORE
  generation, so a timeout never means a missed high-risk message.
- Redaction failure → fail closed: if redaction throws, the message is never forwarded
  to any generation step; it's queued for direct human review instead.
- Auth service down → guests keep full LeadSession functionality (value first, no
  account needed); only the "continue securely" step is blocked, with an honest
  message rather than a silent failure.
