# Gmail Malicious Email Scorer

## Overview

This project is a Gmail Add-on that analyzes opened emails and produces a maliciousness score with a clear and explainable verdict.

The add-on uses a multi-signal risk model combining content heuristics, sender analysis, link intelligence, external threat intelligence, and user-defined blacklist policies to evaluate potential risk.

The goal is to demonstrate security-aware design, explainability, and clean architecture rather than production-grade detection.

---

## Architecture

The solution is implemented as a Google Workspace Gmail Add-on using Google Apps Script.

Flow:

Gmail Message → Add-on Trigger → Analysis Engine → Risk Scoring → UI Card

Components:

- Gmail Add-on UI built with CardService
- Analysis engine implemented in Apps Script
- External threat intelligence via VirusTotal API
- Persistent user policy storage using PropertiesService

---

## Features Implemented

### Email Content Analysis
- Detects suspicious keywords such as "urgent", "verify", "password", and "login"

### Sender Risk Indicators
- Detects free email providers
- Flags unusually long domains

### Link Analysis
- Extracts URLs from email body
- Detects multiple links
- Checks link reputation via VirusTotal

### Risk Scoring Engine
- Combines signals into a single score
- Maps score to status:
  - SAFE
  - SUSPICIOUS
  - HIGH RISK

### Explainability
- Displays categorized reasoning:
  - Content Analysis
  - Link Analysis
  - Sender Analysis
  - Blacklist Policy

### Dynamic Threat Intelligence
- Uses VirusTotal API to enrich link reputation

### User-Managed Blacklist
- Users can add/remove senders
- Persistent storage using PropertiesService
- Blacklisted senders increase risk score

---

## Risk Model

The scoring model follows a simple rules framework, assigning weights to each signal:
- Suspicious keywords → +10 each
- Multiple links → +10
- Malicious link detected → +30
- Free email provider → +15
- Long domain → +10
- Blacklisted sender → +40
The total score is normalized at 100 to keep scoring interpretable and prevent signal inflation.

Score thresholds:

- 0–20 → SAFE
- 21–50 → SUSPICIOUS
- 51+ → HIGH RISK

---

##  APIs Used

### VirusTotal API
Used to check URL reputation and detect malicious links.

---

##  Security Considerations

- API keys stored using Script Properties (not hardcoded)
- No attachment downloads to avoid executing untrusted content
- Explainable scoring for transparency
- User policies stored per-user using User Properties

---
## Limitations
- The detection system relies on predefined rules and patterns, so it may occasionally flag safe emails as suspicious or miss more advanced threats
- The free tier of VirusTotal comes with rate limits, which can slow down or restrict scans
- The system isn’t built for high performance or large-scale production use.

---
## How to Run

1. Open the project in Google Apps Script
2. Deploy as a Gmail Add-on
3. Configure VirusTotal API key in Script Properties:
   - Key: VT_API_KEY
4. Open Gmail and open any email to see analysis

---

## Design Decisions

- Prioritized explainability over detection complexity
- Implemented blacklist to demonstrate policy-driven security
- Used simple scoring approach to keep the process clear and easy to understand
- Focused on high signal-to-effort features

## UI Preview
<img width="346" height="700" alt="image" src="https://github.com/user-attachments/assets/d17725aa-4819-4ef3-be93-6ef4fc0e3521" />
<img width="346" height="717" alt="image" src="https://github.com/user-attachments/assets/3ac465a3-59bb-420a-a2e5-e2a6c2b7454e" />


