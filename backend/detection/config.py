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

# URLs / Attachments
SUSPICIOUS_URL_PATH_SCORE = 10
SHORTENED_URL_SCORE = 5
SUSPICIOUS_ATTACHMENT_SCORE = 12

# Structural / Context
HEADER_ANOMALY_SCORE = 10
REUSED_INDICATOR_SCORE = 15

# Missing / unavailable evidence
INSUFFICIENT_EVIDENCE_SCORE = 0


# Risk band thresholds
LOW_MAX_SCORE = 29
REVIEW_MAX_SCORE = 69
MAX_SCORE = 100
