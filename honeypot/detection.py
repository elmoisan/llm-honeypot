"""
detection.py — Attack detection engine
Analyzes the content of each incoming request.
Uses regex patterns to identify known attack techniques against LLMs.
"""

import re
from dataclasses import dataclass


# ─── Threat levels ──────────────────────────────────────────────────────────

THREAT_LEVELS = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
}


# ─── Pattern library ─────────────────────────────────────────────────────────
# Each entry: (regex_pattern, category, threat_level, human_readable_label)

PATTERNS = [
    # --- Prompt injection ---
    (
        r"ignore\s+(all\s+)?(previous|prior|above)\s+"
        r"(instructions?|prompts?|context|rules?)",
        "prompt_injection", "high", "ignore previous instructions"
    ),
    (
        r"disregard\s+(all\s+)?(previous|prior|above|your)\s+"
        r"(instructions?|rules?|guidelines?)",
        "prompt_injection", "high", "disregard instructions"
    ),
    (
        r"do\s+not\s+follow\s+(your\s+)?(previous\s+)?"
        r"(instructions?|rules?|guidelines?)",
        "prompt_injection", "medium", "do not follow instructions"
    ),
    (
        r"override\s+(your\s+)?(previous\s+)?"
        r"(instructions?|rules?|programming|behavior)",
        "prompt_injection", "high", "override instructions"
    ),
    (r"forget\s+(everything|all)\s+(you\s+)?(know|were told|learned)",
     "prompt_injection", "medium", "forget everything"),

    # --- Jailbreaks ---
    (r"\bDAN\b",
     "jailbreak", "high", "DAN jailbreak attempt"),
    (
        r"you\s+are\s+now\s+(a\s+)?"
        r"(free|uncensored|unrestricted|evil|jailbroken)",
        "jailbreak", "critical", "jailbreak persona injection"
    ),
    (
        r"act\s+as\s+(if\s+)?(you\s+(have\s+no|are\s+without)\s+"
        r"(restrictions?|rules?|guidelines?|ethics?))",
        "jailbreak", "critical", "act without restrictions"
    ),
    (
        r"pretend\s+(you\s+are|to\s+be)\s+(a\s+)?"
        r"(hacker|malicious|evil|unrestricted)",
        "jailbreak", "high", "pretend to be malicious"
    ),
    (r"developer\s+mode",
     "jailbreak", "high", "developer mode jailbreak"),

    # --- System prompt extraction ---
    (
        r"(show|reveal|print|display|output|repeat|tell\s+me|what\s+is)"
        r"\s+(your\s+)?(system\s+prompt|initial\s+prompt|base\s+prompt)",
        "system_prompt_extraction", "high", "system prompt extraction"
    ),
    (
        r"(what\s+(are|were)\s+your|repeat\s+your)\s+"
        r"(instructions?|rules?|guidelines?|directives?)",
        "system_prompt_extraction", "high", "extract instructions"
    ),
    (
        r"summarize\s+(the\s+)?(text|content|instructions?)\s+"
        r"(above|before|prior)",
        "system_prompt_extraction", "medium", "summarize prior context"
    ),

    # --- Role escalation ---
    (
        r"(i\s+am|you\s+are\s+talking\s+to)\s+(your\s+)?"
        r"(admin|administrator|developer|creator|owner|root|superuser)",
        "role_escalation", "high", "admin impersonation"
    ),
    (
        r"(switch\s+to|enable|activate)\s+"
        r"(admin|maintenance|debug|sudo|root)\s+(mode|access)",
        "role_escalation", "critical", "activate admin mode"
    ),
    (r"you\s+must\s+(obey|follow|comply\s+with)\s+me",
     "role_escalation", "medium", "obedience command"),

    # --- Data exfiltration ---
    (
        r"(list|show|give\s+me|display)\s+(all\s+)?"
        r"(users?|accounts?|emails?|passwords?|credentials?)",
        "data_exfiltration", "critical", "user data extraction"
    ),
    (
        r"(show|reveal|print|dump)\s+(your\s+)?"
        r"(database|backend|config|configuration|env|"
        r"environment\s+variables?)",
        "data_exfiltration", "critical", "backend config extraction"
    ),
    (
        r"(what|which)\s+(api\s+keys?|tokens?|secrets?|credentials?)\s+"
        r"(do\s+you\s+have|are\s+stored)",
        "data_exfiltration", "critical", "credential extraction"
    ),

    # --- Recon ---
    (
        r"(what\s+(model|version|engine|llm)|which\s+(model|version|llm))\s+"
        r"(are\s+you|do\s+you\s+use|is\s+this|is\s+running)",
        "recon", "low", "model version probe"
    ),
    (
        r"(list|show|what\s+are)\s+(your\s+)?(available\s+)?"
        r"(models?|endpoints?|routes?|apis?)",
        "recon", "low", "endpoint enumeration"
    ),
]

# Compile all regex patterns once at startup.
COMPILED_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), category, level, label)
    for pattern, category, level, label in PATTERNS
]


# ─── API key pattern detection ───────────────────────────────────────────────

API_KEY_PATTERNS = [
    (r"^sk-[a-zA-Z0-9]{20,}",            "OpenAI key format"),
    (r"^sk-ant-api\d+-[a-zA-Z0-9\-_]+",  "Anthropic key format"),
    (r"^sk-proj-[a-zA-Z0-9\-_]+",        "OpenAI project key format"),
    (r"^Bearer\s+ey[A-Za-z0-9\-_]+",     "JWT token"),
    (r"^[a-f0-9]{32,}$",                  "Generic hex token"),
]

COMPILED_KEY_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), label)
    for pattern, label in API_KEY_PATTERNS
]


# ─── Main detection function ─────────────────────────────────────────────────

@dataclass
class DetectionResult:
    threat_level: str
    categories: list
    detected_patterns: list


def analyze(payload: dict, api_key: str = "") -> DetectionResult:
    """
    Analyze a request payload and API key.
    Returns threat level, attack categories, and matched patterns.
    """
    # Flatten the entire payload to a single string for analysis
    text = _flatten(payload)

    matched_categories = set()
    matched_patterns = []
    max_threat = 0

    # Check each attack pattern
    for compiled, category, level, label in COMPILED_PATTERNS:
        if compiled.search(text):
            matched_categories.add(category)
            matched_patterns.append(label)
            max_threat = max(max_threat, THREAT_LEVELS.get(level, 0))

    # Check if the API key matches known formats (enumeration attempt)
    if api_key:
        for compiled, label in COMPILED_KEY_PATTERNS:
            if compiled.search(api_key):
                matched_categories.add("api_key_enumeration")
                matched_patterns.append(label)
                max_threat = max(max_threat, THREAT_LEVELS["low"])
                break

    # If nothing detected, it's still a recon visit (someone hit our endpoint)
    if not matched_categories:
        matched_categories.add("recon")
        matched_patterns.append("endpoint probe")
        max_threat = THREAT_LEVELS["low"]

    # Convert numeric threat back to string label
    threat_label = next(
        (k for k, v in THREAT_LEVELS.items() if v == max_threat), "low"
    )

    return DetectionResult(
        threat_level=threat_label,
        categories=sorted(matched_categories),
        detected_patterns=matched_patterns,
    )


def _flatten(obj, depth=0) -> str:
    """
    Recursively convert a nested dict/list to a single string.
    This lets us search for patterns anywhere in the payload.
    """
    if depth > 5:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(_flatten(v, depth + 1) for v in obj.values())
    if isinstance(obj, list):
        return " ".join(_flatten(i, depth + 1) for i in obj)
    return str(obj)
