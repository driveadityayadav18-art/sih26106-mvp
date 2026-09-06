"""Run from the project root: python3 -m backend.tests.overall"""

import json

from backend.parser.models import ParsedEmail
from backend.detection.detection import ThreatDetector


# 1. Normal email
normal_email = ParsedEmail()
normal_email.message.from_.address = "alice@company.example"
normal_email.message.reply_to = "alice@company.example"
normal_email.message.subject = "Team meeting"
normal_email.message.body_text = "Our meeting is at 3 pm."
normal_email.authentication.spf.result = "pass"
normal_email.authentication.dkim.result = "pass"
normal_email.authentication.dmarc.result = "pass"

# 2. Urgent payment request with failed authentication and a different Reply-To
payment_email = ParsedEmail()
payment_email.message.from_.address = "accounts@company.example"
payment_email.message.reply_to = "pay@other.example"
payment_email.message.subject = "Payment needed"
payment_email.message.body_text = "Transfer the funds immediately."
payment_email.authentication.spf.result = "fail"
payment_email.authentication.dkim.result = "fail"
payment_email.authentication.dmarc.result = "fail"

# 3. Empty input: shows missing-information notes
missing_email = ParsedEmail()


if __name__ == "__main__":
    detector = ThreatDetector()

    print("Normal email:")
    print(json.dumps(detector.analyze(normal_email), indent=2))

    print("\nPayment email:")
    print(json.dumps(detector.analyze(payment_email), indent=2))

    print("\nMissing information:")
    print(json.dumps(detector.analyze(missing_email), indent=2))
