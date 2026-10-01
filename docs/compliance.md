# Compliance mapping

banbo tags findings with the Ghana-relevant controls they bear on, so a scan doubles as a lightweight compliance check. Mapping is **static and always on** (no AI key needed); AI enrichment adds a plain-English business-impact sentence on top.

## Frameworks

- **Bank of Ghana Cyber & Information Security Directive** — the regulatory baseline for financial institutions operating in Ghana.
- **Data Protection Act, 2012 (Act 843)** — Ghana's data-protection law governing personal-data handling and breach exposure.

## How it appears

Each finding that maps to a control shows a `compliance:` line in text output and a `compliance` array in JSON:

```json
{
  "title": "Missing HSTS header",
  "severity": "medium",
  "asset": "https://app.example.com",
  "compliance": ["BoG Cyber Directive: transport security", "Act 843: safeguarding personal data in transit"]
}
```

!!! note
    The mapping is guidance to help prioritize and communicate risk, not a certified audit. Treat it as a starting point for a formal compliance review, not a substitute for one.
