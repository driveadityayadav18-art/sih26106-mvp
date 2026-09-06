# Detection engine

Person 3's detector reads Person 2's `ParsedEmail` and returns an explainable risk result. It uses fixed rules, makes no network calls, and does not need an API key. The same input and configuration produce the same result.

The score is a **prototype triage score**, not a probability of fraud. A human should review the reasons and missing-information notes.

## Ownership and files

| File | Purpose |
| --- | --- |
| `backend/detection/detection.py` | `ThreatDetector.analyze()` runs the rules and combines results. |
| `backend/detection/config.py` | Weights, thresholds, phrase lists, matching limits and domain/file-type lists. |
| `backend/detection/context.py` | Optional `DetectionContext` and `ReusedIndicator` input objects. |
| `backend/detection/rules/` | Authentication, identity, content, URL/attachment, header, reuse and missing-evidence rules. |
| `backend/tests/test_detection_*.py` | Rule and detector tests. |
| `backend/tests/overall.py` | Three sample parsed-email objects that print detector output. |

Person 2 owns parsing and normalization. Person 1 owns API integration and shared response contracts. Person 5 supplies reuse information. This module does not parse raw MIME or authentication headers, perform DNS verification, fetch links, execute attachments, or search cases.

## Calling the detector

Run Python from the repository root so `backend` imports resolve. Pass the **object**, not `parsed_email.to_dict()` or raw email bytes:

```python
from backend.detection.detection import ThreatDetector

detector = ThreatDetector()
risk = detector.analyze(parsed_email)
```

Person 1's intended flow is:

```text
Raw email -> EmailParser.parse() -> ParsedEmail
                                     |
                                     v
                          ThreatDetector.analyze()
                                     |
                                     v
                           CaseAnalysis.risk
```

The parser already uses the evidence hashing helpers. Detection consumes the resulting metadata. Connecting these modules in `main.py` remains Person 1's task; the detector does not perform that connection itself. Groq review is a separate orchestration feature, not part of these rules.

## Output and scoring

The current return type is a dictionary; there is no typed `RiskAssessment` class yet. For example, an observed SPF failure plus a Reply-To mismatch, with otherwise usable evidence, returns:

```json
{
  "score": 28,
  "band": "LOW",
  "reason_codes": [
    {
      "code": "AUTH_SPF_FAIL",
      "message": "SPF Failed",
      "evidence_path": "authentication.spf.result",
      "weight": 10
    },
    {
      "code": "REPLY_TO_MISMATCH",
      "message": "Reply-To domain differs from sender domain",
      "evidence_path": "message.reply_to",
      "weight": 18
    }
  ],
  "limitations": []
}
```

The detector adds triggered weights, clamps the total to 0–100, and applies the configured bands:

| Score | Band |
| --- | --- |
| 0–29 | `LOW` |
| 30–69 | `REVIEW` |
| 70–100 | `HIGH` |

Each reason code contributes at most once per call. Repeated phrases, URLs, attachments or reuse matches do not multiply that rule's weight. Distinct rules add independently, including related signals such as a credential request and a matching login path. This overlap policy and the prototype weights still need broader evaluation. After clamping, reason weights can sum to more than the returned score.

All 16 required reason codes have implementations. This does not mean every possible phishing technique or wording is covered.

## Rules and evidence paths

Paths below refer to `ParsedEmail`. `[i]` represents the actual list index selected by a rule.

| Code | Weight | Trigger | Evidence path |
| --- | ---: | --- | --- |
| `AUTH_SPF_FAIL` | 10 | Observed SPF `fail`. | `authentication.spf.result` |
| `AUTH_DKIM_FAIL_OR_NONE` | 8 | Observed DKIM `fail` or explicit `none`. | `authentication.dkim.result` |
| `AUTH_DMARC_FAIL` | 12 | Observed DMARC `fail`. | `authentication.dmarc.result` |
| `REPLY_TO_MISMATCH` | 18 | Usable sender and Reply-To domains differ. | `message.reply_to` |
| `DISPLAY_NAME_DOMAIN_MISMATCH` | 10 | A plain email address used as the display name has a different domain from the sender. | `message.from_` |
| `LOOKALIKE_DOMAIN` | 20 | Sender domain is one insertion, deletion or replacement away from a trusted demo domain. | `message.from_.address` |
| `PUNYCODE_DOMAIN` | 10 | A sender-domain part starts with `xn--`. | `message.from_.address` |
| `URGENT_PAYMENT_REQUEST` | 25 | Payment request or specific bank-detail change request with nearby pressure. | `message.subject` or `message.body_text` |
| `CREDENTIAL_REQUEST` | 20 | Direct credential request or the configured password-retention lure. | `message.subject` or `message.body_text` |
| `SENSITIVE_DATA_REQUEST` | 15 | Request to send/upload configured sensitive information. | `message.subject` or `message.body_text` |
| `SUSPICIOUS_URL_PATH` | 10 | Configured path segment plus matching request context. | `message.urls[i].path` |
| `SHORTENED_URL` | 5 | Exact configured shortener hostname. | `message.urls[i].host` |
| `SUSPICIOUS_ATTACHMENT` | 12 | Configured risky final extension or content type. | `message.attachments[i].filename` or `.content_type` |
| `HEADER_ANOMALY` | 10 | Selected malformed-header warning from the parser. | `warnings[i].code` |
| `REUSED_INDICATOR` | 15 | Supplied prior-case observation matches a current-email indicator. | Matching current-email field; context index is also named in the message. |
| `INSUFFICIENT_EVIDENCE` | 0 | Supported checks lack usable evidence. | First unavailable field or relevant parser-warning code. |

Authentication results are observations, not independently verified identities. Missing/default `unknown` is different from explicit DKIM `none`. A rule skips unusable values rather than assigning failure points.

### Identity matching

Domains are extracted from parser-provided plain addresses. Broken ASCII domain parts and parser-marked malformed senders are skipped. This is a basic check, not a complete email-address validator.

Lookalike matching compares whole domains against `TRUSTED_DOMAINS`, currently safe `.example` demonstration names. Exact trusted domains and their subdomains are excluded from this rule. `compamy.example` resembles `company.example`; `store.example` does not. Swapped letters, multi-character visual tricks and lookalikes inside extra subdomains are outside this first version.

The trusted list is only a comparison list, not a safety bypass for other rules. Punycode checking detects the `xn--` prefix at the start of any domain part; it does not decode or validate Punycode. Legitimate international domains can trigger it.

### Content matching

Direct request checks lowercase text, split subject and body separately into sentence-like units, and match whole words/phrases. Actions must precede an item with at most eight intervening words. Payment checks also require pressure within the configured eight-word surrounding window. Simple negation is checked up to four words before the action and between action and item.

- `Transfer the funds immediately` matches action + money + pressure.
- `Update beneficiary banking details immediately` matches the specific bank-change branch.
- `Send your OTP` matches a credential request without requiring urgency.
- `Upload a copy of your passport` matches a sensitive-data request.
- `Never share your OTP` is skipped by the simple negation check.

The additional credential-lure pattern requires password-retention wording, identity verification and account suspension/lock wording within an 80-word span in one field. It can span sentences, but never joins subject to body. `Keep your password private` alone is insufficient. Direct requests and this pattern still produce just one credential reason.

These are English phrase rules, not full language understanding. The word windows and phrase lists are prototype settings in `config.py`.

### URLs and attachments

URL rules read parsed HTTP(S) metadata; there is no raw-URL parsing fallback. Whole slash-separated path segments are matched: `/login` needs credential context; `/verify` and `/update` need credential or sensitive-data context; `/payment` needs a direct payment request, without requiring urgency. The bank-change extension of the urgent-payment rule does not automatically extend these URL mappings.

The request can appear elsewhere in the email; the detector does not prove that it refers to the selected URL. Encoded paths, queries and `login.php` are not matched as `/login`.

Shortener hosts match exactly, ignoring case and one optional trailing dot. `bit.ly.attacker.example` is not `bit.ly`. Attachment checks use the final extension: `invoice.pdf.exe` matches `.exe`, while `invoice.exe.pdf` does not. A risky content type can independently trigger the attachment rule. Partial metadata may support a reason and also produce a missing-evidence note.

### Parser warnings and missing evidence

Header scoring currently selects `MALFORMED_ADDRESS`, `MALFORMED_DATE` and `MALFORMED_RECEIVED_HEADER`. A malformed address warning may concern a recipient, so the reason does not claim that it necessarily describes the sender. Missing Reply-To, missing authentication and private-IP observations do not receive header-anomaly points.

`INSUFFICIENT_EVIDENCE` is emitted once with zero weight. `limitations` explains supported gaps in authentication, sender, text, metadata or selected parser warnings. Empty link/attachment lists, absent Reply-To and absent reuse context do not trigger it by themselves. A path identifying a missing field denotes unavailable evidence, not proof of an attack. Not every malformed metadata combination is covered yet.

## Optional reuse context: Person 1/5 handoff

```python
from backend.detection.context import DetectionContext, ReusedIndicator

context = DetectionContext(
    current_case_id="CASE-CURRENT",
    reused_indicators=[
        ReusedIndicator(
            indicator_type="domain",
            value="other.example",
            related_case_ids=["CASE-OLD"],
            source="local_case_store",
        )
    ],
)
risk = detector.analyze(parsed_email, context=context)
```

Supported kinds are `domain`, `url` and `attachment_sha256`. Domain matching covers sender, Reply-To and usable URL hosts. URLs match exact parser-provided strings; path/query case is preserved. Attachment hashes must be 64 hexadecimal characters and match ignoring case.

A reason requires a nonempty source, another case ID and a match in the current email. Duplicate case IDs are removed; `current_case_id` is excluded when supplied. Without it, the caller must already exclude the current case. No context means no reuse points.

These are detection-local dataclasses, not an approved shared API contract. Person 1/5 must agree on and implement their adapter, retain the supplied context for review, and ensure prior-case observations are trustworthy. The detector does not verify those cases or infer a malicious campaign from reuse alone.

## Tests and sample runner

From the repository root:

```bash
python3 -m pytest backend/tests -q
python3 -m backend.tests.overall
```

`overall.py` prints three manually populated `ParsedEmail` examples: a normal message (0/LOW), an urgent payment with authentication and Reply-To signals (73/HIGH), and empty input (0/LOW with missing-evidence notes). It is not a raw-email parser or a pytest-discovered test file.

The last review ran 417 local tests successfully. A temporary combination with Person 2's parser commit `66e1713` passed 439 tests. These counts are a historical checkpoint; rerun tests after changes. Additional probes checked 3,000 malformed-input variations and 14,641 one-edit comparisons successfully. Passing these checks is not a measured real-world detection accuracy.

With that parser snapshot and the current phrase changes, observed fixture outputs were:

| Fixture | Score/band |
| --- | --- |
| `01_payment_diversion.eml` | 73 / HIGH |
| `02_invoice_followup.eml` | 48 / REVIEW |
| `03_legitimate_internal.eml` | 0 / LOW |
| `04_credential_harvest.eml` | 68 / REVIEW |
| `05_malformed.eml` | 10 / LOW, with missing-evidence reason |

These are observations, not filename-based rules or proof that fixture evaluation is complete. In particular, the credential fixture remains below the existing app's 70-point Tier 2 trigger.

## Known open issues

- Repetitive content can be slow: a roughly 3,000-word stress input exceeded a four-second test limit due to repeated scans.
- Long negative instructions can be misread: `Please do not ever, under any circumstances, send your password` triggers because `not` is beyond the four-word window.
- Quoted examples such as `Security training example: send your OTP` can trigger; the rules do not understand quotation context.
- Some invalid URL paths and wrong-type attachment fields are skipped without a limitation note. Validation is not exhaustive.
- Legitimate payment/login requests, international domains and shared infrastructure can trigger. Unlisted wording can be missed. Weights, overlap handling and thresholds need a larger labeled evaluation set.
- Output currently contains `code`, `message`, `evidence_path` and `weight`; richer shared reason fields and typed risk output remain a contract decision.

## Integration checklist for Person 1

1. Use Person 2's updated parser and pass its `ParsedEmail` object to the detector.
2. Agree on the final risk schema and evidence paths before inserting the result into the shared response. Python `from_` becomes serialized `from`; authentication/warning locations also need a consistent mapping. Current evidence paths target the parser object, not automatically the existing API response.
3. Adapt the parser output separately for existing dictionary-based enrichment and Groq functions. Preserve the frontend's expected shape.
4. Agree with Person 5 on reuse context, if supplied; an existing campaign dictionary is not automatically a `DetectionContext`.
5. Run full API/fixture tests and review the change from the legacy scoring rules. Do not force scores above 70 just to activate an LLM or satisfy a fixture.

No API, parser or teammate-owned implementation changes are made by this documentation.
