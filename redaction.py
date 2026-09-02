"""
Removes sensitive patient information (PHI) from every string before it is
sent to an LLM or saved in an audit log. If raw PHI is provided before
consent and needs to be stored, it is encrypted and never written to logs
in plain text.
"""
import re
import os
from cryptography.fernet import Fernet

# Key must be persisted via env var — otherwise every encrypted guest PHI
# blob becomes permanently unrecoverable the moment the process restarts.
_FERNET_KEY = os.environ.get("FERNET_KEY")
if not _FERNET_KEY:
    _FERNET_KEY = Fernet.generate_key().decode()
    print(
        "WARNING: FERNET_KEY not set in environment — using an ephemeral key. "
        "Encrypted guest PHI will be unrecoverable after this process restarts. "
        "Set FERNET_KEY for any non-throwaway run."
    )
_FERNET = Fernet(_FERNET_KEY.encode() if isinstance(_FERNET_KEY, str) else _FERNET_KEY)

PATTERNS = {
    "IC_NUMBER": re.compile(r"\b\d{6}-?\d{2}-?\d{4}\b|\b[A-Z]\d{7}[A-Z]\b"),
    "PHONE": re.compile(r"\b(?:\+?60|0)1\d[\s-]?\d{3,4}[\s-]?\d{4}\b|\b\+?\d{7,15}\b"),
    "EMAIL": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    # Detects names in phrases like "my name is John Doe".
    # A real system should use NER for more reliable name detection.
    "NAME": re.compile(
        r"(?i:(?:my name is|i am|i'm))\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})"),
}

def redact(text: str) -> tuple[str, bool]:
    """Returns (redacted_text, phi_was_found)."""
    if not text:
        return text, False
    found = False
    out = text
    for label, pattern in PATTERNS.items():
        if label == "NAME":
            def _sub(m):
                nonlocal found
                found = True
                return m.group(0).replace(m.group(1), "[REDACTED]")
            out = pattern.sub(_sub, out)
        else:
            if pattern.search(out):
                found = True
            out = pattern.sub("[REDACTED]", out)
    return out, found

def encrypt(raw_text: str) -> bytes:
    return _FERNET.encrypt(raw_text.encode("utf-8"))

def decrypt(token: bytes) -> str:
    return _FERNET.decrypt(token).decode("utf-8")