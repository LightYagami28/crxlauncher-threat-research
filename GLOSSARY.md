# Glossary

| Term | Meaning |
| --- | --- |
| CRX | Chrome extension package format. |
| Manifest V3 (MV3) | Current Chrome extension platform, which forbids remotely hosted code. |
| `postMessage` | Cross-window messaging API; the extension bridge accepts messages without checking the origin. |
| Trusted Types | Browser defence against DOM XSS, which the extension weakens with a permissive default policy. |
| Offscreen document | Hidden extension page used to run the sandboxed emulator. |
| IOC | Indicator of compromise: domain, IP, extension id, hash. |
| STIX 2.1 | Standard format for sharing threat intelligence. |
| YARA / YARA-X | Pattern-matching rules for files; YARA-X is the Rust implementation used here. |
| Sigma | Generic, vendor-neutral detection rule format for logs. |
| CVSS | Severity score of a vulnerability. |
