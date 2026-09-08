# Security

This crate is supported only as used by Scryer and Weaver. Report vulnerabilities
privately through the affected first-party application's GitHub Security
Advisories. Do not post credentials or vulnerability details in public pull
requests.

The embedding application is the trust boundary: it owns configuration access,
credentials, persisted host-key pins, and authorization/revocation policy.
Private, loopback, and locally routed destinations are legitimate homelab uses.
The tunnel engine is not a sandbox for untrusted destination configuration.
