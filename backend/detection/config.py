# Prototype heuristic risk weights.
# These values are tunable and are not probabilities.

# Authentication
SPF_FAIL_SCORE = 10
DKIM_FAIL_OR_NONE_SCORE = 8
DMARC_FAIL_SCORE = 12

# Identity
REPLY_TO_MISMATCH_SCORE = 18
DISPLAY_NAME_DOMAIN_MISMATCH_SCORE = 10
LOOKALIKE_DOMAIN_SCORE = 20
PUNYCODE_DOMAIN_SCORE = 10

# Safe demo domains for the lookalike rule to compare against.
# Being on this list does not mean every email from the domain is safe.
TRUSTED_DOMAINS = [
    "aicte-demo.example",
    "company.example",
]

# Content
URGENT_PAYMENT_SCORE = 25
CREDENTIAL_REQUEST_SCORE = 20
SENSITIVE_DATA_REQUEST_SCORE = 15

# Keep requests local: the item must follow the action within eight words.
# Pressure must be within eight words of that request. These are prototype
# matching limits, not measured accuracy claims.
REQUEST_GAP = 8
PRESSURE_GAP = 8
NEGATION_WINDOW = 4

PAYMENT_ACTIONS = ("send", "transfer", "pay", "wire", "remit")
PAYMENT_ITEMS = ("funds", "payment", "invoice", "money", "balance")
BANK_CHANGE_ACTIONS = ("update", "change", "replace")
BANK_CHANGE_ITEMS = (
    "beneficiary banking details", "beneficiary bank details", "vendor bank details",
    "bank account details", "payment bank details",
)
PRESSURE_PHRASES = (
    "immediately", "right now", "within an hour", "urgently", "urgent",
    "as soon as possible", "asap", "without delay",
)
CREDENTIAL_ACTIONS = ("send", "share", "provide", "enter", "submit", "give")
CREDENTIAL_ITEMS = (
    "password", "passwords", "otp", "one time code", "one time password",
    "recovery code", "recovery codes", "verification code", "login credentials",
)
# Credential-retention lure: require ALL three groups nearby in one text field.
PASSWORD_RETENTION_PHRASES = (
    "keep existing password", "keep your existing password", "keep your current password",
)
IDENTITY_VERIFICATION_PHRASES = ("verify your identity", "verify identity", "verifying identity")
ACCOUNT_THREAT_PHRASES = (
    "account access will be suspended", "account will be suspended", "account will be locked",
)
CREDENTIAL_LURE_WINDOW = 80
SENSITIVE_ACTIONS = ("send", "share", "upload", "provide", "submit", "give")
SENSITIVE_ITEMS = (
    "passport", "passport copy", "bank account details", "bank account number",
    "aadhaar number", "pan number", "social security number",
)
NEGATIONS = {"no", "not", "never", "don't", "dont", "cannot", "can't", "shouldn't", "mustn't", "avoid"}


# URLs / Attachments
SUSPICIOUS_URL_PATH_SCORE = 10
SHORTENED_URL_SCORE = 5
SUSPICIOUS_ATTACHMENT_SCORE = 12

# Exact host matches only; this is a small prototype list, not reputation data.
URL_SHORTENER_HOSTS = ("bit.ly", "tinyurl.com", "t.co")
URL_PATH_REQUEST_TYPES = {
    "login": ("credential",),
    "verify": ("credential", "sensitive"),
    "update": ("credential", "sensitive"),
    "payment": ("payment",),
}
RISKY_ATTACHMENT_EXTENSIONS = (".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".msi")
RISKY_ATTACHMENT_CONTENT_TYPES = (
    "application/x-msdownload", "application/x-dosexec",
    "application/x-executable", "application/x-sh",
)

# Structural / Context
HEADER_ANOMALY_SCORE = 10
REUSED_INDICATOR_SCORE = 15

# Only observed malformed headers, not routine missing fields or private IPs.
HEADER_ANOMALY_WARNING_CODES = (
    "MALFORMED_ADDRESS", "MALFORMED_DATE", "MALFORMED_RECEIVED_HEADER",
)
# Initial local handoff supports these exact indicator kinds.
REUSED_INDICATOR_TYPES = ("domain", "url", "attachment_sha256")

# Missing / unavailable evidence
INSUFFICIENT_EVIDENCE_SCORE = 0

AUTH_RESULT_VALUES = {
    "spf": ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"),
    "dkim": ("pass", "fail", "none", "neutral", "temperror", "permerror"),
    "dmarc": ("pass", "fail", "none", "bestguesspass", "temperror", "permerror"),
}
INCOMPLETE_PARSER_WARNING_CODES = (
    "MIME_PARSE_WARNING", "HEADER_DECODE_WARNING", "BODY_DECODE_WARNING",
    "URL_PARSE_WARNING", "ATTACHMENT_METADATA_WARNING",
)


# Risk band thresholds
LOW_MAX_SCORE = 29
REVIEW_MAX_SCORE = 69
MAX_SCORE = 100
