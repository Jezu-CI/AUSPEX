---
title: Auspex — passive IT/OT CMDB (open source)
description: "Auspex is an open-source passive CMDB for IT and OT/ICS networks: agentless asset inventory and network segmentation control from mirrored traffic, built on NetBox and Zeek, with signed audit evidence for NIS2, DORA and IEC 62443."
lang: en
---

<div lang="en" markdown>

# Auspex — passive IT/OT CMDB

**Auspex inventories assets and checks network segmentation by passive
listening**, for IT and industrial (OT/ICS) environments. No agent, no service
account, and not a single packet sent on the monitored networks.

[Download](../telecharger.md){ .md-button .md-button--primary }
[Source code](https://github.com/Jezu-CI/AUSPEX){ .md-button }

*The full documentation is in French. This page summarizes the project in English.*

## What Auspex does

- **Observed, not declared, inventory.** Every asset seen on the network is
  identified (operating system, vendor, model, firmware, role) with a
  confidence score and the evidence behind it: Siemens PLCs, Niagara
  supervisors, HART gateways, Moxa, Hirschmann and RUGGEDCOM devices; HMIs and
  engineering workstations are told apart.
- **Continuous segmentation control.** Every flow between zones is compared
  with the declared rules (CSV or Excel): undeclared flows, expired rules still
  in use, administration from a less trusted tier, IT-to-OT flows bypassing the
  industrial DMZ.
- **Evidence for NIS2, DORA and IEC 62443.** Signed audit exports per
  framework, verifiable without Auspex; each finding carries its regulatory
  references; alerts to the SIEM (syslog CEF or JSON, HTTPS webhook).
- **Built into NetBox.** The observed inventory sits next to the declared one,
  with the differences between them, a dashboard, an interactive map and
  hardened access control (MFA, security keys, smart cards, LDAPS, OIDC, SAML).

## How it works

1. **The sensor listens** to a SPAN port or a network TAP (Docker image, or a
   hardened appliance ISO whose capture interface never transmits). It runs
   Zeek with CISA's ICSNPP parsers: EtherNet/IP (CIP), S7comm, Modbus, DNP3,
   BACnet, OPC UA, OMRON FINS, HART-IP, GE SRTP and PROFINET.
2. **The central server analyses**: asset identification, flow compliance,
   reconciliation with NetBox, alerts and audit exports.
3. **Teams consult** NetBox, receive alerts in their SIEM and hand the signed
   exports to auditors.

## Proven, not promised

Every change is automatically tested on the real product: full central
install, real NetBox, real browser, real directory and identity providers, the
appliance booted in a virtual machine (no frame sent on the capture interface),
and **real public industrial packet captures**. Releases are signed with
Sigstore and ship with SLSA provenance.

## License and author

Free software under the **GNU AGPL v3** with an attribution notice. Designed by
Yann Mathon, cybersecurity consultant; code written with the assistance of
Claude (Anthropic) and verified by automated tests on every change.

</div>
