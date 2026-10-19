#!/usr/bin/env python3
"""Vendor-shaped mock API for Cloudflare and NextDNS.

Cloudflare and NextDNS are SaaS control planes with no self-hostable server, so the
only way to exercise Tally's *native pull* code paths end to end is to serve the
documented response shapes locally over real TLS. Everything on the Tally side is
real: real reqwest/rustls client, real Bearer/X-Api-Key auth, real pagination,
real request routing, projection and admission.

The records served here are loaded from ./payload.json, which the lab populates
from genuinely observed traffic (the real DNS resolver's query log, and the real
calls made through the LiteLLM proxy).
"""
import json
import os
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PAYLOAD = json.load(open(os.environ["PAYLOAD"]))
CF_TOKENS = frozenset({
    os.environ["CF_API_TOKEN"],
    os.environ["CF_ANALYTICS_TOKEN"],
    os.environ["CF_AI_GATEWAY_TOKEN"],
})
ND_KEY = os.environ["ND_KEY"]
HITLOG = os.environ["HITLOG"]
LOG = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.headers.get("Host", "-"), fmt % args))

    def _send(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _record(self, kind):
        LOG.append(kind)
        try:
            with open(HITLOG, "a") as fh:
                fh.write("%s %s %s\n" % (self.headers.get("Host", "-"), self.command, self.path))
        except OSError:
            pass

    # ---- Cloudflare -----------------------------------------------------
    def _cf_authorized(self):
        authorization = self.headers.get("Authorization")
        return (
            authorization is not None
            and authorization.startswith("Bearer ")
            and authorization.removeprefix("Bearer ") in CF_TOKENS
        )

    def do_GET(self):
        url = urlparse(self.path)
        path, query = url.path, parse_qs(url.query)
        self._record(path)
        host = (self.headers.get("Host") or "").split(":")[0]

        if host == "api.nextdns.io":
            if self.headers.get("X-Api-Key") != ND_KEY:
                return self._send(403, {"errors": [{"code": "forbidden"}]})
            if self.headers.get("Authorization"):
                # Tally must never send the key as a bearer credential.
                return self._send(400, {"errors": [{"code": "unexpected-authorization"}]})
            parts = [p for p in path.split("/") if p]
            if len(parts) == 3 and parts[0] == "profiles" and parts[2] == "logs":
                cursor = (query.get("cursor") or [None])[0]
                pages = PAYLOAD["nextdns_pages"]
                index = 0 if cursor is None else int(cursor.split("_")[-1])
                page = pages[index] if index < len(pages) else {"data": []}
                return self._send(200, page)
            return self._send(404, {"errors": [{"code": "not-found"}]})

        if host == "api.cloudflare.com":
            if not self._cf_authorized():
                return self._send(403, {"success": False, "errors": [{"message": "bad token"}]})
            parts = [p for p in path.split("/") if p]
            # /client/v4/accounts/<acct>/...
            if len(parts) >= 4 and parts[:3] == ["client", "v4", "accounts"]:
                rest = parts[4:]
                if rest == ["one", "integrations"]:
                    app = (query.get("application") or [""])[0]
                    result = [{k: v for k, v in i.items() if k != "_app"}
                              for i in PAYLOAD["casb_integrations"] if i["_app"] == app]
                    return self._send(200, {"result": result, "success": True,
                                            "errors": [], "messages": [],
                                            "result_info": {"page": 1, "total_pages": 1}})
                if rest == ["ai-gateway", "gateways"]:
                    return self._send(200, {"result": PAYLOAD["ai_gateways"], "success": True,
                                            "errors": [], "messages": [],
                                            "result_info": {"page": 1, "total_pages": 1}})
                if len(rest) == 4 and rest[:2] == ["ai-gateway", "gateways"] and rest[3] == "logs":
                    logs = PAYLOAD["ai_gateway_logs"].get(rest[2], [])
                    return self._send(200, {"result": logs, "success": True,
                                            "errors": [], "messages": [],
                                            "result_info": {"page": 1, "total_pages": 1}})
            return self._send(404, {"success": False, "errors": [{"message": "no route"}]})

        return self._send(421, {"error": "unexpected host"})


if __name__ == "__main__":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.environ["CERT"], os.environ["KEY"])
    srv = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    sys.stderr.write("mock vendor API listening on 8443 (TLS)\n")
    srv.serve_forever()
