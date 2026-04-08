# Bounce-CTI — Purpose & Vision

## What is it?

Bounce-CTI is an **autonomous Cyber Threat Intelligence (CTI) investigation tool**. Given a single observable — a domain name, an IP address, or a file hash — it deploys an LLM agent (Claude) that pivots across multiple threat intelligence sources, aggregates findings into an interactive graph, and delivers a structured analyst report.

## Why does it exist?

Traditional CTI investigation is manual, slow, and scattered:
- An analyst receives an IOC (e.g. a suspicious domain)
- They open 5–10 browser tabs (VirusTotal, Shodan, URLScan, crt.sh, WHOIS...)
- They copy-paste results, look for patterns, and pivot manually
- An hour later they have a partial picture, undocumented, hard to share

**Bounce-CTI automates the entire first-pass investigation**, letting the analyst start at a higher level — reading a structured graph and a written summary — instead of starting from scratch.

## Core objectives

1. **Speed up triage**: Turn a 1-hour manual investigation into a 3-minute automated one.
2. **Never miss obvious pivots**: The agent systematically runs crt.sh, passive DNS, RDAP, threat intel lookups, and infrastructure fingerprinting — in the right order.
3. **Filter noise automatically**: CDN ranges, shared hosting, parking nameservers, sinkholes, DynDNS providers — all defused before pivoting, with tags visible in the UI.
4. **Surface discriminating markers**: favicon hashes, JARM/JA3 fingerprints, certificate serials, registrant emails, NS sets — high-signal pivots that link attacker infrastructure.
5. **Present results as a live graph**: Every finding becomes a node/edge, built in real time. The analyst sees the investigation unfold.
6. **Let the analyst go further**: Click any node to pivot from it. Copy any node or the full graph as JSON for downstream tooling (MISP, STIX, reports).

## Who is it for?

- Security analysts performing IOC triage and threat hunting
- SOC teams investigating suspicious indicators from alerts
- Students and researchers learning CTI investigation methodology
- Anyone who needs to quickly understand the infrastructure behind a domain, IP, or malware sample

## What it is NOT

- A SIEM or detection platform
- A real-time monitoring service
- A replacement for human analyst judgment
- A mass-scanning tool

The agent deliberately caps pivot depth (3 hops) and API budget (~60 calls) to stay focused and avoid noise amplification.
