#!/usr/bin/env python3
"""Turn the lab's real DNS resolver log into every source format Tally accepts.

One body of genuinely observed traffic drives all of the DNS-shaped connectors, so
the comparison across connectors is apples to apples:

  out/generic-dns.csv              -> generic DNS file connector
  out/cloudflare-gateway.ndjson    -> Cloudflare Gateway Logpush (push receiver)
  out/nextdns.csv                  -> NextDNS CSV export
  payload.json                     -> NextDNS Logs API + Cloudflare control-plane mocks
"""
import csv
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone

LINE = re.compile(
    r'^(?P<ts>\S+) \[INFO\] (?P<client>[0-9.]+):\d+ - \d+ '
    r'"(?P<qtype>[A-Z]+) IN (?P<name>[^ ]+) \S+ \d+ \S+ \d+" (?P<rcode>[A-Z]+)'
)

raw = subprocess.run(
    ["docker", "logs", "-t", "tally-lab-coredns-1"],
    capture_output=True, text=True, check=True,
).stderr or ""
raw += subprocess.run(
    ["docker", "logs", "-t", "tally-lab-coredns-1"],
    capture_output=True, text=True, check=True,
).stdout

records = []
seen = set()
for line in raw.splitlines():
    m = LINE.match(line.strip())
    if not m:
        continue
    if m.group("qtype") != "A":
        continue
    name = m.group("name").rstrip(".").lower()
    if not name or "." not in name or name.endswith(".lab"):
        continue
    ts = m.group("ts")
    # Docker stamps RFC3339 with nanoseconds; Tally wants second precision.
    dt = datetime.fromisoformat(ts.split(".")[0] + "+00:00").astimezone(timezone.utc)
    key = (dt.replace(microsecond=0).isoformat(), name)
    if key in seen:
        continue
    seen.add(key)
    records.append({
        "ts": dt.replace(microsecond=0),
        "name": name,
        "client": m.group("client"),
        "rcode": m.group("rcode"),
    })

records.sort(key=lambda r: r["ts"])
if not records:
    sys.exit("no DNS records parsed from the resolver log")
print(f"parsed {len(records)} real A-record queries for "
      f"{len({r['name'] for r in records})} distinct hostnames")

def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

# --- generic DNS file connector -----------------------------------------
with open("out/generic-dns.csv", "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["timestamp", "query", "client_ip", "response_code", "action"])
    for r in records:
        w.writerow([iso(r["ts"]), r["name"], r["client"], r["rcode"], "resolved"])

# --- Cloudflare Gateway Logpush (gateway_dns dataset) -------------------
with open("out/cloudflare-gateway.ndjson", "w") as fh:
    for i, r in enumerate(records):
        fh.write(json.dumps({
            "QueryID": hashlib.sha256(f"{r['ts']}{r['name']}".encode()).hexdigest()[:32],
            "Datetime": iso(r["ts"]),
            "QueryName": r["name"],
            "QueryNameReversed": ".".join(reversed(r["name"].split("."))),
            "QueryType": 1,
            "QueryTypeName": "A",
            "ResolverDecision": "allowedOnNoPolicyMatch",
            "SrcIP": r["client"],
            "Email": f"analyst{i % 3}@lab.example",
            "DeviceID": f"device-{i % 3}",
            "DeviceName": f"laptop-{i % 3}",
            "Location": "lab",
            "Protocol": "udp",
            "RData": [{"type": "A", "data": "203.0.113.10"}],
            "Categories": ["Technology"],
            "PolicyID": "",
            "PolicyName": "",
        }) + "\n")

# --- NextDNS CSV export -------------------------------------------------
with open("out/nextdns.csv", "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["timestamp", "domain", "query_type", "dnssec", "protocol", "client_ip",
                "status", "reasons", "destination_country", "root_domain", "device_id",
                "device_name", "device_model", "device_local_ip", "matched_name",
                "client_name", "prompt"])
    for i, r in enumerate(records):
        w.writerow([iso(r["ts"]), r["name"], "A", "true", "DNS-over-HTTPS", r["client"],
                    "allowed", "", "US", ".".join(r["name"].split(".")[-2:]),
                    f"D{i % 3:03d}AB", f"Workstation {i % 3}", "MacBookPro18,3",
                    "10.20.0.%d" % (10 + i % 3), r["name"], "nextdns-macos",
                    "LAB_PROMPT_CANARY_MUST_NOT_SURVIVE"])

# --- Zscaler NSS web log ------------------------------------------------
CANARY = "LAB_PROMPT_CANARY_MUST_NOT_SURVIVE"
with open("out/zscaler.ndjson", "w") as fh:
    for i, r in enumerate(records):
        fh.write(json.dumps({
            "time": int(r["ts"].timestamp()),
            "record_id": f"nss-{i}",
            "login": f"analyst{i % 3}@lab.example",
            "department": "Research",
            "device_owner": f"Analyst {i % 3}",
            "device_hostname": f"laptop-{i % 3}",
            "url": f"https://{r['name']}/v1/chat?prompt={CANARY}",
            "action": "Allowed",
            "url_category": "AI and ML Applications",
            "protocol": "HTTPS",
            "client_ip": r["client"],
            "server_ip": "203.0.113.10",
            "server_port": 443,
            "request_size": 342 + i,
            "response_size": 1204 + i,
            "user_agent": CANARY,
            "cookies": f"session={CANARY}",
            "request_content": CANARY,
            "response_content": CANARY,
        }) + "\n")

# --- Palo Alto Strata URL log -------------------------------------------
with open("out/palo-alto.ndjson", "w") as fh:
    for i, r in enumerate(records):
        fh.write(json.dumps({
            "TimeGenerated": int(r["ts"].timestamp()) * 1_000_000,
            "SequenceNumber": 7003061085139300000 + i,
            "Type": "url",
            "SourceAddress": r["client"],
            "DestinationAddress": "203.0.113.11",
            "DestinationPort": 443,
            "SourceUser": f"analyst{i % 3}@lab.example",
            "SourceDeviceHost": f"device-pa-{i % 3}",
            "URL": f"{r['name']}/v1/messages?prompt={CANARY}",
            "Application": "ssl",
            "URLCategory": "AI and ML",
            "Protocol": "tcp",
            "Action": "allow",
            "BytesSent": 511 + i,
            "BytesReceived": 2048 + i,
            "HTTPHeaders": f"Authorization: {CANARY}",
            "FileURL": f"https://files.invalid/{CANARY}",
            "UserAgent": CANARY,
            "ThreatPayload": CANARY,
        }) + "\n")

# --- NextDNS Logs API pages (mock transport, real records) --------------
pages, page = [], []
for i, r in enumerate(records):
    page.append({
        "timestamp": iso(r["ts"]),
        "domain": r["name"],
        "root": ".".join(r["name"].split(".")[-2:]),
        "encrypted": True,
        "protocol": "DNS-over-HTTPS",
        "clientIp": r["client"],
        "client": "apple",
        "device": {"id": f"D{i % 3:03d}AB", "name": f"Workstation {i % 3}",
                   "model": "MacBookPro18,3", "localIp": "10.20.0.%d" % (10 + i % 3)},
        "status": "default",
    })
    if len(page) == 8:
        pages.append(page)
        page = []
if page:
    pages.append(page)
nextdns_pages = []
for idx, p in enumerate(pages):
    meta = {"pagination": {"cursor": f"page_{idx + 1}"}} if idx + 1 < len(pages) else {}
    nextdns_pages.append({"data": p, "meta": meta})

# --- Cloudflare Zero Trust Gateway aggregate groups ---------------------
# --- Cloudflare CASB + AI Gateway ---------------------------------------
casb = [
    {"_app": "OPENAI", "id": "3d1f0a5e-6b7c-4d8e-9f01-2a3b4c5d6e7f",
     "status": "Healthy", "is_paused": False, "updated": iso(records[-1]["ts"]),
     "application": {"id": "openai-app", "name": "OpenAI"}},
    {"_app": "ANTHROPIC", "id": "7c2e9b41-8d3a-4f56-b7c8-9d0e1f2a3b4c",
     "status": "Healthy", "is_paused": True, "updated": iso(records[-1]["ts"]),
     "application": {"id": "anthropic-app", "name": "Anthropic"}},
]
ai_gateways = [{"id": "lab-gateway"}, {"id": "research-gateway"}]
ai_gateway_logs = {
    "lab-gateway": ([{"provider": "openai"}] * 7 + [{"provider": "anthropic"}] * 4
                    + [{"provider": "workers-ai"}] * 2),
    "research-gateway": [{"provider": "google-ai-studio"}] * 3,
}

json.dump({
    "nextdns_pages": nextdns_pages,
    "casb_integrations": casb,
    "ai_gateways": ai_gateways,
    "ai_gateway_logs": ai_gateway_logs,
}, open("payload.json", "w"), indent=1)

print(f"wrote out/generic-dns.csv, out/cloudflare-gateway.ndjson, out/nextdns.csv, "
      f"payload.json ({len(nextdns_pages)} NextDNS pages)")
