# Agent rules

## Project

This project is for the GenWorks Open Agent Hackathon.

The goal is a cybersecurity application that tests websites and applications. The user provides a URL or uploads source code. Either way, the AI creates a safe environment and runs the tests there.

The application uses libraries to track the latest zero-day CVEs and tests the user's application against them.

These rules apply to every change in this repository.

## Data and security

Hackathon section 11 applies to every dataset, download, and API in this repository.

### 11.1 Permitted

- Publicly available datasets with appropriate licences
- Small static datasets committed to the repository
- Automated download scripts that need no login or manual steps
- Public APIs called at runtime
- Synthetic or simulated data, clearly identified

### 11.2 Not permitted

- Confidential, proprietary or restricted data the participant is not authorised to use
- Personal data without authorisation and appropriate safeguards
- Committed API keys, passwords, tokens, certificates or credentials
- Datasets used in breach of their licence terms
- Malware, exploit code, credential harvesting or harmful automation

Do not commit API keys, passwords, tokens, certificates, or credentials. Do not add malware, exploit code, credential harvesting, or harmful automation. Label synthetic data as synthetic. A new data source must pass `backend/src/data_policy.py` before it is fetched or committed.

## Document the change

After editing files in a folder, update that folder's `spec.md`. If that folder has no `spec.md`, create one. The spec records what changed in that folder.

## Follow the instructions only

Do the requested work and nothing beyond it. Do not add extra files, features, refactors, or behavior.

## Test before claiming done

Before saying the work is finished, add a few tests that check the change works as intended, and run them.
