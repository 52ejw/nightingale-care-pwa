"""
Rules for choosing an opening based on channel, identity level, and time.
Never ask for information the user has already provided.
Falls back from an exact match to a channel or global default.
"""
from datetime import datetime

def daypart(ts: datetime = None) -> str:
    ts = ts or datetime.now()
    h = ts.hour
    if 5 <= h < 12: return "morning"
    if 12 <= h < 18: return "afternoon"
    return "evening"

# key = (channel, identity_level, daypart) ; "*" = wildcard
CHANNEL_RULES = {
    ("staff_referral", "identified", "*"): {
        "greeting": "Hi {name_or_there}, {staff_name} from the clinic mentioned you were asking about {topic} earlier — happy to pick up from there whenever you're ready.",
        "value_events_offered": ["topic_summary"],
    },
    ("instagram_comment", "anonymous", "*"): {
        "greeting": "Hey! Thanks for the comment on our post — I'm Nightingale, the clinic's assistant. I can answer questions about {topic} right now, no sign-up needed. What's on your mind?",
        "value_events_offered": ["personal_note", "clinic_stat"],
    },
    ("tiktok_comment", "anonymous", "*"): {
        "greeting": "Saw your comment on our TikTok 👋 I'm Nightingale — ask me anything about {topic}, totally anonymous for now.",
        "value_events_offered": ["personal_note", "clinic_stat"],
    },
    ("facebook_comment", "anonymous", "*"): {
        "greeting": "Thanks for reaching out on our Facebook post. I'm Nightingale, the clinic's virtual assistant — ask away, no account needed yet.",
        "value_events_offered": ["personal_note", "clinic_stat"],
    },
    ("instagram_ad_click", "anonymous", "*"): {
        "greeting": "Thanks for clicking through — I can answer questions about {topic} right now without any sign-up.",
        "value_events_offered": ["clinic_stat"],
    },
    ("google_ad_click", "anonymous", "*"): {
        "greeting": "Hi, I'm Nightingale. You clicked in about {topic} — ask me anything, no account needed.",
        "value_events_offered": ["clinic_stat"],
    },
    ("lead_form", "identified", "*"): {
        # already gave an email -> never ask for it again, skip straight to substance
        "greeting": "Hi {name_or_there}, thanks for submitting your details about {topic}. I've got your email on file already — let's talk through what's on your mind.",
        "value_events_offered": ["personal_note"],
    },
    ("google_reviews", "anonymous", "*"): {
        "greeting": "Thanks for reaching out after reading our reviews. I'm Nightingale — ask me anything about the clinic or {topic}, no sign-up required.",
        "value_events_offered": ["clinic_stat"],
    },
    ("website_widget", "anonymous", "morning"): {
        "greeting": "Morning! I'm Nightingale. You were looking at our {topic} page — happy to answer questions before your day gets busy.",
        "value_events_offered": ["clinic_stat"],
    },
    ("website_widget", "anonymous", "*"): {
        "greeting": "Hi, I'm Nightingale. I noticed you were reading about {topic} — ask me anything, no account needed.",
        "value_events_offered": ["clinic_stat"],
    },
}

DEFAULT_RULE = {
    "greeting": "Hi, I'm Nightingale, the clinic's assistant. Ask me anything — no sign-up needed yet.",
    "value_events_offered": ["clinic_stat"],
}

def resolve_opening(channel: str, identity_level: str, topic: str = "your visit",
                     name: str = None, staff_name: str = None, ts: datetime = None) -> dict:
    dp = daypart(ts)
    for key in [(channel, identity_level, dp), (channel, identity_level, "*")]:
        if key in CHANNEL_RULES:
            rule = CHANNEL_RULES[key]
            break
    else:
        rule = DEFAULT_RULE
    text = rule["greeting"].format(
        name_or_there=name or "there",
        topic=topic,
        staff_name=staff_name or "our team",
    )
    return {"greeting": text, "value_events_offered": rule["value_events_offered"]}