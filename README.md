# Nightingale Care PWA

Nightingale is an AI-assisted intake and triage assistant for a fertility/women's health clinic.

It supports:

- Anonymous guest conversations and social-media enquiries
- General, non-diagnostic health information
- Secure patient signup and intake
- A continuously updated patient profile
- Automated risk gating and clinician escalation
- Staff/clinician review and response

**Stack:** Flask + SQLite + vanilla HTML/JavaScript + Anthropic API

The LLM is used only for low-stakes conversational responses. **Risk decisions are handled deterministically before any LLM response.**

## Setup

Requires **Python 3.12+**.

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

For a clean installation, `requirements.txt` should include:

```text
Flask
cryptography
anthropic
python-dotenv
pytest
```

### Environment

Copy `.env.example` to `.env`.

Required:

- `FERNET_KEY` — encryption key for guest PHI
- `ANTHROPIC_API_KEY` — optional; without it, the app uses safe fallback responses

Optional:

- `NIGHTINGALE_DB` — SQLite database path; defaults to `nightingale.db`

Generate a Fernet key with:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Run

```bash
python app.py
```

Open:

```text
http://localhost:5000
```

The application seeds three demo staff accounts:

| Username        | Role      | Password   |
| --------------- | --------- | ---------- |
| `nurse_amy`     | Nurse     | `demo1234` |
| `dr_lim`        | Clinician | `demo1234` |
| `frontdesk_wan` | Staff     | `demo1234` |

## Tests

```bash
pytest tests/test_nightingale.py -v
```

Tests cover:

- Guest → patient conversion
- Honest value-event behaviour
- High-risk detection and escalation
- Escalation payloads
- Patient memory updates
- PHI redaction
- Cross-patient access control
- Trust response
- Audit-log privacy

Tests use a temporary SQLite database and do not modify the main database.

## Security & Privacy

### Risk gating

Risk is assessed **before response generation**. High, medium, and ambiguous concerns are routed to human staff rather than handled by the LLM.

### PHI redaction

`redaction.py::redact()` runs on guest and patient messages before downstream processing.

It removes:

- Names
- IC numbers
- Phone numbers
- Email addresses

Guest PHI that must temporarily be retained is encrypted with Fernet and kept separate from the redacted message.

### Audit logs

Audit logs contain only metadata and hashed identifiers. Raw message content is never stored in audit logs.

### RBAC

`require_role()` protects all staff and patient routes.

Patients can only access their own sessions. Nurses and clinicians can access clinical escalation functions; the general staff role cannot access raw guest PHI.

### Guest retention

Guest-only data is retained for up to 30 days for abandonment analytics. Guest PHI is also removed after the retention period.

## Known Limitations

- Guest-data purging currently runs at application startup rather than as a scheduled nightly job.
- Redaction failures currently fail closed by returning an error rather than forwarding unredacted data.
- Without an Anthropic API key, the application uses safe canned responses.
- The application is a development/demo system and uses synthetic data only.
