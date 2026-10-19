#!/usr/bin/env python3
"""Generate genuine AI-provider network traffic from inside the lab network.

Each request performs a real DNS lookup through the lab's CoreDNS resolver and a
real TLS connection to the provider. Requests are unauthenticated and are expected
to be rejected by the provider; the point is that the resolver log and the flow are
real observed traffic, not hand-authored records.
"""
import socket
import ssl
import sys
import urllib.error
import urllib.request

TARGETS = [
    ("https://api.openai.com/v1/models", "openai"),
    ("https://api.anthropic.com/v1/models", "anthropic"),
    ("https://generativelanguage.googleapis.com/v1beta/models", "google gemini"),
    ("https://api.mistral.ai/v1/models", "mistral"),
    ("https://api.cohere.ai/v1/models", "cohere"),
    ("https://api.groq.com/openai/v1/models", "groq"),
    ("https://huggingface.co/api/models", "hugging face"),
    ("https://api.perplexity.ai/chat/completions", "perplexity"),
    ("https://api.deepseek.com/v1/models", "deepseek"),
    ("https://api.together.xyz/v1/models", "together"),
]

ctx = ssl.create_default_context()
for url, label in TARGETS:
    host = urllib.parse.urlparse(url).hostname
    try:
        addrs = socket.getaddrinfo(host, 443, socket.AF_INET)
        ip = addrs[0][4][0]
    except OSError as exc:
        print(f"DNS-FAIL {host}: {exc}")
        continue
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "tally-lab/1.0"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            status = resp.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    except Exception as exc:  # noqa: BLE001
        status = f"ERR {type(exc).__name__}"
    print(f"{label:15s} {host:45s} A={ip:16s} HTTP={status}")
