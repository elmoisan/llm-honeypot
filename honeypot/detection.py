"""
detection.py — Attack detection engine
Analyzes the content of each incoming request.
Uses regex patterns to identify known attack techniques against LLMs.
"""

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass


# ─── Threat levels ──────────────────────────────────────────────────────────

THREAT_LEVELS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


# In-memory sliding window used for simple IP-based rate limiting.
# This is intentionally lightweight and sufficient for a honeypot.
_RATE_WINDOW_SECONDS = 60
_RATE_BUCKETS: defaultdict[str, deque[float]] = defaultdict(deque)


def check_rate_limit(ip: str, limit_per_minute: int = 60) -> tuple[bool, int]:
    """Return whether an IP crossed the configured request threshold."""
    if not ip or ip in {"unknown", "", "testclient"}:
        return False, 0

    now = time.monotonic()
    bucket = _RATE_BUCKETS[ip]

    while bucket and now - bucket[0] > _RATE_WINDOW_SECONDS:
        bucket.popleft()

    bucket.append(now)
    count = len(bucket)
    return count > limit_per_minute, count


# ─── Pattern library ─────────────────────────────────────────────────────────
# Each entry: (regex_pattern, category, threat_level, human_readable_label)

PATTERNS = [
    # --- Prompt injection ---
    (
        r"ignore\s+(all\s+)?(previous|prior|above)\s+"
        r"(instructions?|prompts?|context|rules?)",
        "prompt_injection",
        "high",
        "ignore previous instructions",
    ),
    (
        r"disregard\s+(all\s+)?(previous|prior|above|your\s+previous|"
        r"your\s+prior|your)\s+(instructions?|rules?|guidelines?)",
        "prompt_injection",
        "high",
        "disregard instructions",
    ),
    (
        r"do\s+not\s+follow\s+(your\s+)?(previous\s+)?"
        r"(instructions?|rules?|guidelines?)",
        "prompt_injection",
        "medium",
        "do not follow instructions",
    ),
    (
        r"override\s+(your\s+)?(previous\s+)?"
        r"(instructions?|rules?|programming|behavior)",
        "prompt_injection",
        "high",
        "override instructions",
    ),
    (
        r"forget\s+(everything|all)\s+(you\s+)?(know|were told|learned)",
        "prompt_injection",
        "medium",
        "forget everything",
    ),

    # --- Jailbreaks ---
    (r"\bDAN\b", "jailbreak", "high", "DAN jailbreak attempt"),
    (
        r"you\s+are\s+(now\s+)?(an?\s+)?"
        r"(free|uncensored|unrestricted|evil|jailbroken)",
        "jailbreak",
        "critical",
        "jailbreak persona injection",
    ),
    (
        r"act\s+as\s+(if\s+)?(you\s+(have\s+no|are\s+without)\s+"
        r"(restrictions?|rules?|guidelines?|ethics?))",
        "jailbreak",
        "critical",
        "act without restrictions",
    ),
    (
        r"pretend\s+(you\s+are|to\s+be)\s+(a\s+)?"
        r"(hacker|malicious|evil|unrestricted)",
        "jailbreak",
        "high",
        "pretend to be malicious",
    ),
    (r"developer\s+mode", "jailbreak", "high", "developer mode jailbreak"),
    # ChatGPT mode and variants
    (
        r"\bchatgpt\s+mode\b",
        "jailbreak",
        "critical",
        "ChatGPT mode activation",
    ),
    (r"\bbasedgpt\b", "jailbreak", "critical", "BasedGPT jailbreak"),
    (r"\balt\s+mode\b", "jailbreak", "high", "AltMode jailbreak"),
    (r"\btrain\s+mode\b", "jailbreak", "critical", "TRAIN mode jailbreak"),
    (r"\bvile\s+mode\b", "jailbreak", "critical", "VILE mode jailbreak"),
    (r"\b(test\s+)?mode\s+enabled?\b", "jailbreak", "high",
     "test mode activation"),
    # Role-play exploitation
    (
        r"(roleplay|role\s+play|play\s+a\s+role)\s+as\s+"
        r"(a\s+)?(hacker|criminal|attacker|gpt\s+without|evil)",
        "jailbreak",
        "high",
        "malicious role-play",
    ),
    (
        r"imagine\s+(you|yourself)\s+are\s+"
        r"(a\s+)?(unrestricted|unfiltered|uncensored|evil)",
        "jailbreak",
        "high",
        "imagine persona jailbreak",
    ),
    # Hypothetical exploitation
    (
        r"(hypothetically|suppose|if|assume)\s+you\s+"
        r"(were|had|could|were\s+to|were\s+able\s+to)\s+"
        r"(jailbreak|bypass|ignore|circumvent)",
        "jailbreak",
        "high",
        "hypothetical constraint bypass",
    ),
    # Direct constraint removal
    (
        r"(remove|delete|reset|clear|reset|forget)\s+your\s+"
        r"(safety|ethical|content|output)\s+"
        r"(guidelines?|constraints?|rules?|filters?)",
        "jailbreak",
        "critical",
        "remove safety constraints",
    ),
    # Code execution and interpretation
    (
        r"(execute|run|eval|interpret)\s+this\s+"
        r"(code|script|command|python|bash)",
        "jailbreak",
        "critical",
        "code execution attempt",
    ),
    # Prefix injection
    (
        r"(prefix|start|begin)\s+your\s+response\s+with\s+"
        r"['\"]?(i\s+have\s+no|i\s+don'?t\s+have|ignore)",
        "jailbreak",
        "high",
        "response prefix injection",
    ),
    # Token smuggling
    (
        r"(render|decode|translate|interpret|parse)\s+this\s+"
        r"(base64|hex|encoded|encrypted)",
        "jailbreak",
        "medium",
        "encoded payload obfuscation",
    ),

    # --- System prompt extraction ---
    (
        r"(show|reveal|print|display|output|repeat|tell\s+me\s+your|"
        r"what\s+is)\s+(your\s+|the\s+|me\s+your\s+)?"
        r"(system\s+prompt|initial\s+prompt|base\s+prompt|instructions?)",
        "system_prompt_extraction",
        "high",
        "system prompt extraction",
    ),
    (
        r"(what\s+(are|were)\s+your|repeat\s+your|reveal\s+your)\s+"
        r"(base\s+|system\s+)?"
        r"(instructions?|rules?|guidelines?|directives?)",
        "system_prompt_extraction",
        "high",
        "extract instructions",
    ),
    (
        r"summarize\s+(the\s+)?(text|content|instructions?)\s+"
        r"(above|before|prior)",
        "system_prompt_extraction",
        "medium",
        "summarize prior context",
    ),

    # --- Role escalation ---
    (
        r"(i\s+am|you\s+are\s+talking\s+to)\s+(your\s+)?"
        r"(admin|administrator|developer|creator|owner|root|superuser)",
        "role_escalation",
        "high",
        "admin impersonation",
    ),
    (
        r"(switch\s+to|enable|activate)\s+"
        r"(admin|maintenance|debug|sudo|root)\s+(mode|access)",
        "role_escalation",
        "critical",
        "activate admin mode",
    ),
    (r"you\s+must\s+(obey|follow|comply\s+with)\s+me",
     "role_escalation",
     "medium",
     "obedience command"),

    # --- Data exfiltration ---
    (
        r"(list|show|give\s+me|display)\s+(all\s+)?"
        r"(users?|accounts?|emails?|passwords?|credentials?)",
        "data_exfiltration",
        "critical",
        "user data extraction",
    ),
    (
        r"(show|reveal|print|dump)\s+(your\s+)?"
        r"(database|backend|config|configuration|env|"
        r"environment\s+variables?)",
        "data_exfiltration",
        "critical",
        "backend config extraction",
    ),
    (
        r"(what|which)\s+(api\s+keys?|tokens?|secrets?|credentials?)\s+"
        r"(do\s+you\s+have|are\s+stored)",
        "data_exfiltration",
        "critical",
        "credential extraction",
    ),

    # --- Recon ---
    (
        r"(what\s+(model|version|engine|llm)|which\s+(model|version|llm))\s+"
        r"(are\s+you|do\s+you\s+use|is\s+this|is\s+running)",
        "recon",
        "low",
        "model version probe",
    ),
    (
        r"(list|show|what\s+are)\s+(your\s+)?(available\s+)?"
        r"(models?|endpoints?|routes?|apis?)",
        "recon",
        "low",
        "endpoint enumeration",
    ),
]

# Compile all regex patterns once at startup.
COMPILED_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), category, level, label)
    for pattern, category, level, label in PATTERNS
]


# ─── API key pattern detection ───────────────────────────────────────────────

API_KEY_PATTERNS = [
    (r"^sk-[a-zA-Z0-9]{20,}", "OpenAI key format"),
    (r"^sk-ant-api\d+-[a-zA-Z0-9\-_]+", "Anthropic key format"),
    (r"^sk-proj-[a-zA-Z0-9\-_]+", "OpenAI project key format"),
    (r"^Bearer\s+ey[A-Za-z0-9\-_]+", "JWT token"),
    (r"^[a-f0-9]{32,}$", "Generic hex token"),
]

COMPILED_KEY_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), label)
    for pattern, label in API_KEY_PATTERNS
]


# ─── Main detection function ─────────────────────────────────────────────────

@dataclass
class DetectionResult:
    """Result of analyzing a request for threats and attack patterns."""

    threat_level: str
    categories: list
    detected_patterns: list


def analyze(
    payload: dict,
    api_key: str = "",
    ip: str | None = None,
    rate_limit_triggered: bool = False,
) -> DetectionResult:
    """
    Analyze a request payload and API key.
    Returns threat level, attack categories, and matched patterns.
    Unknown traffic is classified as a generic probe instead of an attack.
    """
    del ip
    text = _flatten(payload)

    matched_categories = set()
    matched_patterns = []
    max_threat = 0

    for compiled, category, level, label in COMPILED_PATTERNS:
        if compiled.search(text):
            matched_categories.add(category)
            matched_patterns.append(label)
            max_threat = max(max_threat, THREAT_LEVELS.get(level, 0))

    if api_key:
        for compiled, label in COMPILED_KEY_PATTERNS:
            if compiled.search(api_key):
                matched_categories.add("api_key_enumeration")
                matched_patterns.append(label)
                max_threat = max(max_threat, THREAT_LEVELS["low"])
                break

    if rate_limit_triggered:
        matched_categories.add("rate_limit_abuse")
        matched_patterns.append("burst traffic detected")
        max_threat = max(max_threat, THREAT_LEVELS["medium"])

    if not matched_categories:
        if not text.strip():
            matched_categories.add("recon")
            matched_patterns.append("empty request probe")
            max_threat = THREAT_LEVELS["low"]
        else:
            matched_categories.add("generic_probe")
            matched_patterns.append("unknown request pattern")
            max_threat = THREAT_LEVELS["low"]

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
