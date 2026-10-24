"""Secret redaction.

Every string that leaves a tool (to the LLM), lands in a trace file, or ends up
in the final report passes through :func:`redact`. The goal is that the agent
can still *see that* a credential is present (so it can report it) without the
secret value itself ever being reproduced.
"""

from __future__ import annotations

import re

# 1) Tokens recognised by their own shape (a distinctive prefix/format), wherever they appear.
_TOKEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Cloud providers
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("google-oauth-secret", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{28}\b")),
    ("digitalocean-token", re.compile(r"\bdo[opr]_v1_[a-f0-9]{64}\b")),
    # Source hosting / package registries / CI
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("gitlab-token", re.compile(r"\bgl(?:pat|ptt|dt|rt)-[A-Za-z0-9_-]{20,}\b")),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("pypi-token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}")),
    ("databricks-token", re.compile(r"\bdapi[a-f0-9]{32}\b")),
    ("atlassian-token", re.compile(r"\bATATT3[A-Za-z0-9_=-]{50,}")),
    # AI / ML APIs
    ("api-key", re.compile(r"\bsk-(?:ant-|proj-|live-|svcacct-)?[A-Za-z0-9_-]{20,}\b")),  # OpenAI, Anthropic, ...
    ("huggingface-token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("groq-key", re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b")),
    ("replicate-token", re.compile(r"\br8_[A-Za-z0-9]{37}\b")),
    # Payments / messaging / SaaS
    ("stripe-key", re.compile(r"\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("square-token", re.compile(r"\bsq0(?:atp|csp)-[0-9A-Za-z_-]{22,}\b")),
    ("shopify-token", re.compile(r"\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b")),
    ("slack-token", re.compile(r"\bxox[abeprs]-[A-Za-z0-9-]{10,}\b")),
    ("sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("twilio-key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("mailgun-key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),
    ("mailchimp-key", re.compile(r"\b[0-9a-f]{32}-us\d{1,2}\b")),
    ("telegram-bot-token", re.compile(r"\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b")),
    ("notion-token", re.compile(r"\b(?:secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{40,})\b")),
    ("linear-key", re.compile(r"\blin_api_[A-Za-z0-9]{40}\b")),
    ("postman-key", re.compile(r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b")),
    # Generic formats
    ("age-secret-key", re.compile(r"\bAGE-SECRET-KEY-1[A-Z0-9]{58}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

# 2) Secrets recognised by their surrounding context: (kind, pattern with groups (prefix)(secret)).
_CONTEXT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("azure-key", re.compile(r"(?i)(\b(?:AccountKey|SharedAccessKey)=)([A-Za-z0-9+/=]{20,})")),
    ("auth-header", re.compile(r"(?i)(\b(?:Bearer|Basic)\s+)(?=\S*\d)([A-Za-z0-9._~+/-]{16,}=*)")),  # needs a digit: not prose
    ("slack-webhook", re.compile(r"(https://hooks\.slack\.com/services/)([A-Za-z0-9/]{20,})")),
    ("discord-webhook", re.compile(r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/)([0-9]+/[A-Za-z0-9_-]{20,})")),
]

_PRIVATE_KEY_BLOCK = re.compile(
    r"(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)(.*?)(-----END [A-Z0-9 ]*PRIVATE KEY-----)",
    re.DOTALL,
)
# A lone base64 line, e.g. the body of a key block when only one line is shown.
_BASE64_LINE = re.compile(r"(?m)^(\s*)[A-Za-z0-9+/]{60,}={0,2}\s*$")

# scheme://user:password@host
_URL_CREDENTIALS = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^:/\s@]+:)([^@\s/]+)(@)")

_SECRET_NAME = (
    r"[\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key"
    r"|private[_-]?key|client[_-]?secret|credentials?|auth[_-]?key)[\w.-]*"
)
# The name may be followed by a closing quote and/or bracket: `password=`, `"password":`, `cfg["password"] =`.
_NAME_END = r"[\"']?\]?\s*(?::=|=>|[:=])\s*"
_ASSIGNMENT = re.compile(
    r"(?i)(?P<prefix>\b" + _SECRET_NAME + _NAME_END + r")"
    r"(?P<quote>[\"']?)(?P<value>[^\"'\s,;#}]{4,})(?P=quote)"
)

# 3) A bare `key` / `*_key` / `*-key` name. Many harmless names end in "key", so these are masked only when
#    the value itself looks like a token (see _looks_like_token) and the name is not a known harmless one.
_KEY_ASSIGNMENT = re.compile(
    # key | snake_key | dotted.key | kebab-key | camelKey (case-sensitive "Key", so "monkey" never matches)
    r"(?i)(?P<prefix>\b(?P<name>(?:[\w.-]*[_.-])?key|[A-Za-z0-9]*[a-z0-9](?-i:Key))" + _NAME_END + r")"
    r"(?P<quote>[\"']?)(?P<value>[^\"'\s,;#}]{16,})(?P=quote)"
)
# Compared against whole name parts (cache_key -> {"cache","key"}), never substrings, so hmac_key still counts.
_HARMLESS_KEY_PARTS = frozenset({
    "public", "primary", "foreign", "sort", "partition", "cache", "idempotency", "unique", "lookup",
    "dict", "map", "row", "index", "sequence", "group", "order", "join", "composite", "natural", "range",
    "redis", "translation", "i18n", "message", "label", "react", "item", "object", "s3", "column", "table",
})


def _name_parts(name: str) -> set[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)  # camelCase -> camel Case
    return {p.lower() for p in re.split(r"[\s_.-]+", spaced) if p}


_PLACEHOLDER_HINTS = (
    "changeme", "change_me", "change-me", "your", "xxx", "***", "example", "dummy",
    "placeholder", "sample", "redacted", "<", "{{", "${", "$(", "%(", "none", "null",
    "todo", "fixme", "replace", "insert", "secret_here", "key_here",
)


def _is_reference_or_placeholder(value: str, quoted: bool) -> bool:
    low = value.lower()
    if low.startswith("$") or low in {"true", "false", "none", "null", "nil", "required"}:
        return True
    if any(hint in low for hint in _PLACEHOLDER_HINTS):
        return True
    if not quoted:
        # Unquoted right-hand sides are usually code: os.environ[...], settings.X, f(x)
        if any(ch in value for ch in "()[]"):
            return True
        if re.fullmatch(r"[A-Za-z_][\w]*(\.[A-Za-z_]\w*)+", value):
            return True
        # Plain identifiers (e.g. `token = token`) carry no secret.
        if re.fullmatch(r"[A-Za-z_]+", value):
            return True
    return False


def _looks_like_token(value: str) -> bool:
    """A value that plausibly is a credential: long, no spaces, mixes letters and digits."""
    return (
        len(value) >= 16
        and any(c.isdigit() for c in value)
        and any(c.isalpha() for c in value)
        and not re.fullmatch(r"[a-z]+(?:[_.-][a-z0-9]+)*", value)  # word_like_names_v2, dotted.paths
    )


def _mask(kind: str, value: str) -> str:
    return f"<REDACTED:{kind} len={len(value)}>"


def redact(text: str) -> str:
    """Return ``text`` with credential-like values replaced by markers."""
    if not text:
        return text

    text = _PRIVATE_KEY_BLOCK.sub(lambda m: f"{m.group(1)}<REDACTED:private-key-body>{m.group(3)}", text)
    for kind, pattern in _TOKEN_PATTERNS:
        text = pattern.sub(lambda m, k=kind: _mask(k, m.group(0)), text)
    for kind, pattern in _CONTEXT_PATTERNS:
        text = pattern.sub(lambda m, k=kind: f"{m.group(1)}{_mask(k, m.group(2))}", text)
    text = _URL_CREDENTIALS.sub(lambda m: f"{m.group(1)}{_mask('url-password', m.group(2))}{m.group(3)}", text)

    def _assignment(m: re.Match[str]) -> str:
        value, quote = m.group("value"), m.group("quote")
        if value.startswith("<REDACTED") or _is_reference_or_placeholder(value, bool(quote)):
            return m.group(0)
        return f"{m.group('prefix')}{quote}{_mask('secret', value)}{quote}"

    def _key_assignment(m: re.Match[str]) -> str:
        value, quote = m.group("value"), m.group("quote")
        if (
            value.startswith("<REDACTED")
            or _name_parts(m.group("name")) & _HARMLESS_KEY_PARTS
            or _is_reference_or_placeholder(value, bool(quote))
            or not _looks_like_token(value)
        ):
            return m.group(0)
        return f"{m.group('prefix')}{quote}{_mask('secret', value)}{quote}"

    text = _ASSIGNMENT.sub(_assignment, text)
    text = _KEY_ASSIGNMENT.sub(_key_assignment, text)
    text = _BASE64_LINE.sub(lambda m: f"{m.group(1)}<REDACTED:base64-blob>", text)
    return text


def contains_unredacted_secret(text: str) -> bool:
    """True if ``text`` still contains something :func:`redact` would mask."""
    return bool(text) and redact(text) != text
