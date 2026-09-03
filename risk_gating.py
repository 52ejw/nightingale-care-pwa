"""
Checks every patient message for risk before generating a response.
Uses exact phrase matching for high-risk cases, broader keywords for related
phrases, and flags unclear cases as Medium risk instead of guessing.
"""
import re
from datetime import datetime, timezone

# High risk/urgent phrases e.g. chest pain, suicide mentions, stroke signs
HIGH_RISK_MUST_CATCH = [
    r"crushing chest pain", r"chest pain", r"difficulty breathing",
    r"can'?t breathe", r"heavy bleeding", r"bleeding heavily",
    r"want to hurt myself", r"hurt myself", r"kill myself", r"suicide",
    r"can'?t feel (my|one) side", r"face (is )?drooping", r"slurred speech",
    r"passed out", r"lost consciousness", r"having a seizure",
    r"vomiting blood", r"coughing up blood",
    r"throat (is )?swelling", r"tongue (is )?swelling",
    r"severe allergic reaction", r"overdose",
    r"took too many (pills|medications)", r"unbearable pain",
]

# Phrases that suggest something concerning but not immediately life-threatening
MED_RISK_KEYWORDS = [
    r"fever", r"worsening", r"getting worse", r"not sure", r"worried",
    r"dizzy", r"vomit", r"rash spreading", r"in pain",
    r"faint", r"fainted", r"nauseous", r"persistent pain",
    r"swelling", r"numbness", r"weakness", r"dehydrated",
]

# Vague phrases that don't clearly say what's wrong — treated as medium risk
# rather than guessing, since we can't be sure it's safe just from the wording
AMBIGUOUS_PATTERNS = [
    r"feels? funny", r"doesn'?t feel right", r"something'?s off", r"weird feeling",
    r"feels? strange", r"not feeling like myself", r"feeling unusual",
    r"something is wrong", r"feels? different",
]

def assess_risk(message: str) -> dict:
    text = message.lower() # normalize case so matching isn't case-sensitive
    ts = datetime.now(timezone.utc).isoformat() # timestamp for when this check happened

    # First, check for anything clearly high-risk — this takes priority over everything else
    for pat in HIGH_RISK_MUST_CATCH:
        if re.search(pat, text):
            return {
                "risk_level": "high",
                "risk_reason": f"matched high-risk phrase pattern: '{pat}'",
                "confidence": "high",
                "risk_provenance": ts,
            }

    # Check for unclear language flagged as medium risk rather than ignored,
    # since we can't safely rule out something serious just from unclear wording
    for pat in AMBIGUOUS_PATTERNS:
        if re.search(pat, text):
            return {
                "risk_level": "medium",
                "risk_reason": "vague/ambiguous symptom description — cannot safely rule out risk from text alone",
                "confidence": "low",
                "risk_provenance": ts,
            }

    # Then check for known medium-risk keywords
    for pat in MED_RISK_KEYWORDS:
        if re.search(pat, text):
            return {
                "risk_level": "medium",
                "risk_reason": f"matched medium-risk keyword: '{pat}'",
                "confidence": "med",
                "risk_provenance": ts,
            }
    # Nothing matched, treat as low risk
    return {
        "risk_level": "low",
        "risk_reason": "no high/medium risk markers detected",
        "confidence": "med",
        "risk_provenance": ts,
    }