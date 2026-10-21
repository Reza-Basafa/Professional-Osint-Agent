# NEXUS — Professional OSINT Agent

A consent-based public-source research tool that runs through GitHub Actions and produces a polished PDF report plus JSON observations.

## Features
- Domain: public DNS address, MX, NS, TXT, SPF, DMARC, and checks for a short list of common DKIM selectors.
- URL: public IP resolution, HTTP status, page title, selected security headers, and TLS details where available.
- Username: checks selected public profile URLs; optional Sherlock integration extends public-profile discovery. Candidate matches require manual verification.
- Email: syntax, public MX, SPF, DMARC, and common DKIM-selector checks. No mailbox access or breach database lookup.
- Phone: public numbering-plan validation and region/carrier labels where available; no GPS or subscriber lookup.
- Output: print-ready dark PDF and machine-readable JSON in a downloadable Actions artifact.
- Safety: explicit authorization confirmation, bounded timeouts, public-IP checks, and no redirect following.

## Run on GitHub
1. Open Actions → NEXUS OSINT Report → Run workflow.
2. Select a target type and enter the value.
3. For username targets only, optionally enable **use_sherlock** for an extended public-profile scan. This can take longer and may be rate-limited.
4. Confirm you have permission to investigate the target.
5. Start the workflow. Download the nexus-osint-report artifact from the completed run; it contains PDF and JSON.

Examples: domain = example.com; url = https://example.com; username = public handle; phone = international format with country code.

## Run locally
Python 3.10+:
    python -m pip install -r requirements.txt
    python osint_agent.py --type domain --target example.com --out reports

## Limitations
This is public-source research software, not a commercial intelligence database. A missing result does not prove an account or record does not exist. Public profile checks may produce false positives because of soft-404 pages, redirects, or anti-bot protections. Sherlock scans public profile URLs but can also return false positives and may be rate-limited. SPF/DMARC results are DNS observations; DKIM is tested against a limited list of common selectors, so a missing match does not prove DKIM is absent. Treat findings as leads and verify independently.

Use only for lawful research on systems and data you own or have explicit permission to assess. Do not use findings to harass, stalk, dox, or make consequential decisions about a person.
