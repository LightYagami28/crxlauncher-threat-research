# Coordinated Vulnerability Disclosure Notice

**To:** Google Chrome Trust & Safety Team / Chrome Security Group  
**CC:** CERT Coordination Center (CERT/CC), US-CERT / CISA  
**Date of Filing:** October 20, 2026  
**Subject:** Emergency Security Advisory: Active Malicious MV3 Bypass, 0-Day Remote Privilege Escalation & Universal Trusted Types Neutralization in Extension `kiilhncajadbgbmdbdcopdpnmdhlbdle` (1,000,000+ Active Users)  

---

## 1. Summary of Incident

The undersigned independent security research team has concluded a forensic investigation into **CRXLauncher 1.1.0** (ID: `kiilhncajadbgbmdbdcopdpnmdhlbdle`). The extension currently has over **1,000,000 active installations** on Google Chrome Web Store.

Our technical reverse-engineering confirms that the extension violates core Chromium extension security policies and introduces high-severity vulnerabilities affecting all installed browsers:

1. **Circumvention of Manifest V3 Remotely Hosted Code Ban:** The extension downloads arbitrary `.zip` and `.crx` files from remote servers, decompresses them in memory via JSZip, and evaluates arbitrary JavaScript inside an offscreen document sandboxed iframe (`offscr.html` / `sb.html`) using `new Function()`.
2. **Zero-Day Remote Privilege Escalation via `window.postMessage`:** In `assets/js/brg.js`, an isolated-world message listener accepts API invocation commands (`"chrome: call method"`) from any web page without verifying `event.origin`. Any website visited by a victim can invoke privileged Chrome extension APIs, including `tabs.executeScript` (mapped to `scripting.executeScript` in the main world of other tabs) and `downloads.download`.
3. **Global Disabling of W3C Trusted Types:** In `assets/js/vendor.js`, the extension overwrites `window.trustedTypes.createPolicy` with a passthrough default policy on all visited websites (`http://*/*` and `https://*/*`), removing DOM XSS defenses for all 1,000,000+ users across banking, enterprise, and cloud services.
4. **Coercive Syndicated Distribution:** The extension is pushed onto users via forced bundling and download gating on warez portals such as FileCR, and operates as an unvetted dropper for affiliate marketing fraud and link hijacking.

---

## 2. Action Items Requested from Google

1. **Emergency Delisting:** Immediately delist `kiilhncajadbgbmdbdcopdpnmdhlbdle` from the Chrome Web Store.
2. **Automated Remote Killswitch:** Trigger an automated killswitch to remotely disable and uninstall the extension across all active user installations.
3. **Pipeline Scanning Rule Update:** Introduce automated static scanning rules for extensions bundling ZIP decompression libraries (e.g. JSZip) paired with `chrome.offscreen` `IFRAME_SCRIPTING` dynamic function constructors.

---

## 3. Vulnerability Verification PoC

Security auditors may verify the unauthenticated `postMessage` flaw by loading `poc/postmessage_audit.html` on any local HTTP server while running the extension with normal permissions.

---
*Submitted for public defensive research and coordinated consumer protection.*
