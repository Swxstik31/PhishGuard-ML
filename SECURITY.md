# Security Policy

## Scope
PhishGuard-ML performs static URL analysis. This means it evaluates the lexical string structure of a URL mathematically using Machine Learning.

## Security Design
- **Untrusted Input:** Submitted URLs are treated as untrusted strings.
- **No Network Access:** The application NEVER intentionally visits, crawls, resolves (DNS), or executes any submitted URL. It does not load external assets or perform automated browser headless execution on target URLs.
- **Privacy Safe:** The application does not store prediction history server-side and does not log complete submitted URLs in persistent production logs.

## Reporting
If you discover a vulnerability in the application (e.g., an input validation bypass, a path traversal flaw, or a denial of service vector), please open an Issue in this repository tagged with "Security" or contact the repository maintainer directly. Do not post exploit payloads publicly without coordinating a fix.
