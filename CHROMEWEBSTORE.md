# Chrome Web Store Listing — PhishGuard Web

> Last Updated: 2026-09-24

## Store Listing

**Extension Name** [REQUIRED]  
PhishGuard Web

**Short Description** [REQUIRED]  
Real-time threat triage and phishing defense. Detects malicious pages, alerts immediately, and provides instant SOC tab remediation.

**Detailed Description** [REQUIRED]  
PhishGuard Web is an active defense and threat triage extension designed to protect users against evasive phishing attacks and malicious websites.

Key Features:
- Real-Time Phishing Detection: Continuously evaluates completed page loads against threat intelligence feeds.
- Advanced Anti-Evasion Protection: Detects attacks that attempt parameter manipulation and evasive URL query string packing.
- Instant SOC Triage Console: Open tabs are merged and triaged into a tri-state matrix (Malicious, Safe, Unknown).
- Desktop & Badge Alerts: Immediate visual warning badges on malicious tabs accompanied by desktop notifications.
- One-Click Remediation: Instantly terminate malicious tabs directly from the console.
- False Positive Reporting: Quickly export threat telemetry to your clipboard and locally suppress alerts for trusted sites.

How to Use:
1. Ensure the PhishGuard Web intelligence backend is running locally.
2. Browse normally. If a threat is detected, a red badge and notification alert will appear.
3. Click the PhishGuard icon in your toolbar to view the triage console.
4. Review malicious or unverified tabs, inspect threat evidence, and terminate unsafe tabs with one click.

Privacy & Security:
PhishGuard Web operates transparently. URL inspections are evaluated against your configured local intelligence backend and established threat feeds without collecting personal identity, financial, or browsing history data.

Support & Feedback:
For questions, support, or bug reports, please consult the repository documentation.

**Category** [REQUIRED]  
Productivity

**Single Purpose** [REQUIRED]  
Triages browser tabs in real time to detect and neutralize phishing threats.

**Primary Language** [REQUIRED]  
English

## Graphics & Assets

| Asset | Dimensions | Status | Filename |
|-------|-----------|--------|----------|
| Store Icon [REQUIRED] | 128×128 PNG | ✅ Ready | `extension/icons/icon-128.png` |
| Extension Icon 48 | 48×48 PNG | ✅ Ready | `extension/icons/icon-48.png` |
| Extension Icon 16 | 16×16 PNG | ✅ Ready | `extension/icons/icon-16.png` |
| Screenshot 1 [REQUIRED] | 1280×800 | ⬜ Not created | |
| Small Promo Tile [RECOMMENDED] | 440×280 | ⬜ Not created | |

## Permissions Justification

| Permission | Type | Justification |
|------------|------|---------------|
| `tabs` | permissions | Required to inspect active web page URLs and titles during navigation for real-time phishing detection, and to enable closing malicious tabs from the triage console. |
| `storage` | permissions | Required to cache threat analysis verdicts in `chrome.storage.session` for 10 minutes to prevent API spam and store user-reported false positive suppressions. |
| `notifications` | permissions | Required to send desktop alert notifications when a confirmed malicious website is opened. |
| `http://127.0.0.1:8787/*` | host_permissions | Required to communicate with the local PhishGuard threat intelligence triage backend API. |
| `http://localhost:8787/*` | host_permissions | Required as an alternate local loopback endpoint for the intelligence backend API. |

## Privacy & Data Use

### Data Collection

**Does the extension collect user data?** No

| Data Type | Collected? | Transmitted Off-Device? | Purpose | Shared with Third Parties? |
|-----------|-----------|------------------------|---------|---------------------------|
| Personally identifiable info | No | No | N/A | No |
| Health info | No | No | N/A | No |
| Financial info | No | No | N/A | No |
| Authentication info | No | No | N/A | No |
| Personal communications | No | No | N/A | No |
| Location | No | No | N/A | No |
| Web history | No | No | Only active tab URLs are evaluated against the local user backend | No |
| User activity | No | No | N/A | No |
| Website content | No | No | N/A | No |

### Data Use Certification
- [x] Data is NOT sold to third parties
- [x] Data is NOT used for purposes unrelated to the extension's core functionality
- [x] Data is NOT used for creditworthiness or lending purposes

## Distribution

**Visibility**: Public  
**Regions**: All regions  

## Developer Info

**Publisher Name**: PhishGuard Cyber Defense  
**Contact Email**: security@phishguard-internal.local  

## Version History

| Version | Date | Changes | Status |
|---------|------|---------|--------|
| 1.0.0 | 2026-09-24 | Initial production-grade release of Manifest V3 extension and backend. | Ready |
