# CRXLauncher: Threat Intelligence, Vulnerability Dossier & Forensic Analysis

[![License: CC BY 4.0](https://img.shields.io/badge/License-CC_BY_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)
[![Threat Level: Critical](https://img.shields.io/badge/Threat_Level-CRITICAL-red.svg)]()
[![Victim Base: 1,000,000+](https://img.shields.io/badge/Active_Users-1%2C000%2C000%2B-orange.svg)]()
[![Manifest: V3](https://img.shields.io/badge/Manifest-V3_Bypass-yellow.svg)]()

This repository contains comprehensive technical documentation, reverse-engineering analyses, detection engineering rules (YARA, Sigma, STIX 2.1), and a responsible disclosure dossier regarding **CRXLauncher** (`kiilhncajadbgbmdbdcopdpnmdhlbdle`), a malicious extension dropper on the official Google Chrome Web Store with over **1,000,000 active users**.

---

## Executive Summary

**CRXLauncher** claims to be a developer utility that allows users to install and test `.crx` extensions without enabling Chromium Developer Mode. In reality, forensic reverse engineering reveals:

1. **Manifest V3 Remotely Hosted Code Evasion:** It implements a virtual extension machine (CEVM) that fetches arbitrary ZIP/CRX archives from remote servers, decompresses them in memory via bundled JSZip, stores files in `chrome.storage.local`, and evaluates arbitrary code inside a sandboxed iframe within an offscreen document (`offscr.html`, `IFRAME_SCRIPTING`) via `new Function()`.
2. **Zero-Day Remote Privilege Escalation via `window.postMessage` (CVSS 9.6 - Critical):** The isolated-world content script (`assets/js/brg.js`), injected into all HTTP/HTTPS web pages, listens for cross-origin window messages without validating `event.origin`. Any malicious website visited by an affected user can invoke privileged Chrome extension APIs, including injecting arbitrary scripts into any other open browser tab (`scripting.executeScript`) and downloading arbitrary files to disk.
3. **Universal Neutralization of W3C Trusted Types (CVSS 7.5 - High):** Injected at `document_start` into the `MAIN` execution world of every website visited, `assets/js/vendor.js` replaces `window.trustedTypes.createPolicy` with an insecure passthrough default policy, disabling DOM XSS defenses for all websites loaded by the 1,000,000+ victims.
4. **Adware / Affiliate Fraud Syndicate Tie-In:** Corroborated by telemetry and community intelligence, the extension is distributed as a forced prerequisite for file downloads on software piracy portals (notably **FileCR**), acting as an unvetted pipeline to inject affiliate link hijacking, cookie stuffing, and search engine redirects.

---

## Vulnerability Overview

| Identifier | Vulnerability | Affected Component | CVSS v3.1 | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **CRX-0DAY-2026-01** | Zero-Day Unauthenticated `postMessage` Extension API Execution | `assets/js/brg.js` | **9.6** | Critical |
| **CRX-VULN-2026-02** | Universal Neutralization of W3C Trusted Types (DOM XSS Protection) | `assets/js/vendor.js` | **7.5** | High |
| **CRX-VULN-2026-03** | Arbitrary Remote Package Installation via `externally_connectable` | `manifest.json` / `bg.js` | **8.8** | High |
| **CRX-VULN-2026-04** | Covert Hostname Exfiltration via GA4 Telemetry | `assets/js/bg.js` | **5.3** | Medium |

---

## Repository Structure

```
├── README.md                                    # This document
├── RESEARCH_REPORT.md                           # Exhaustive technical whitepaper
├── CRXLauncher_Deep_Forensic_Analysis_2026.pdf  # Compiled publication-ready PDF paper
├── DISCLOSURE_NOTICE.md                         # Coordinated disclosure report for Google & CERTs
├── rules/
│   ├── crxlauncher.yar                          # YARA detection rule
│   ├── sigma_crxlauncher_network.yml            # Sigma rule for DNS/HTTP C2 network traffic
│   └── sigma_crxlauncher_filesystem.yml         # Sigma rule for EDR filesystem/storage persistence
├── threat-intel/
│   ├── iocs.json                                # Indicators of Compromise in JSON
│   ├── iocs.csv                                 # Indicators of Compromise in CSV
│   └── stix_bundle.json                         # STIX 2.1 Threat Intel Objects bundle
└── poc/
    └── postmessage_audit.html                   # Defensive audit script to verify postMessage origin flaw
```

---

## Indicators of Compromise (IoCs)

### Extension Metadata
- **Store Extension ID:** `kiilhncajadbgbmdbdcopdpnmdhlbdle`
- **Store URL:** `https://chromewebstore.google.com/detail/kiilhncajadbgbmdbdcopdpnmdhlbdle`
- **Version:** `1.1.0`
- **SHA-256 (Public Key):** `9bf7ebc815349e5d4cb0d829391ab1a1ea1d07c08deea2cb6962cf75f32a0c64`

### Network Indicators
- **C2 Domain:** `crxlauncher.com`, `www.crxlauncher.com`
- **Cloudflare Anycast IPs:** `104.21.86.100`, `172.67.217.211`
- **IPv6:** `2606:4700:3034::ac43:d9d3`, `2606:4700:3032::6815:5664`
- **Telemetry ID:** `G-Z14126F651` (API Secret: `NqpDuhxQTVSqAVkEgU4nPQ`)
- **Mail Servers:** `mx.zoho.com`, `mx2.zoho.com`, `mx3.zoho.com`

---

## Coordinated Disclosure Status

- **Vendor Contacted:** Google Chrome Web Store Trust & Safety Team
- **Advisory Date:** October 20, 2026
- **Status:** Under active coordinated disclosure and public community review.
- **Copyright Compliance Notice:** This repository contains strictly original defensive research, deobfuscated structural extracts under fair use / security analysis provisions, and open-source detection engineering rules. No proprietary binary code is distributed.

---

## License

The documentation and research in this repository are licensed under the [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/) license. Detection engineering rules (YARA, Sigma) are released into the public domain under the [MIT License](LICENSE).
