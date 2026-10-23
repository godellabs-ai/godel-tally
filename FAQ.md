# Gödel Tally FAQ

## What does Tally store?

Tally stores one unique finding per governed subject and evidence kind, plus first/last use, count,
source connector links, and optional endpoint, user, destination, and workload attribution. It does
retain normalized AI-only telemetry in ClickHouse with configurable retention, alongside persistent
agent inventory. The Overview Findings table presents individual observations with server-side filters
and pagination. Raw source payloads and non-AI logs are discarded. See [AI estate](https://godel-labs.ai/docs/tally/inventory-and-findings).

## What is a provider?

A provider is the route through which a model is used. It may be a hosted API, a cloud AI platform,
an AI gateway, or a local runtime. For example, Ollama is a provider and Llama 3.2 is a model.

## How do provider and model sanctions differ?

Unsanctioning a provider makes usage through that provider unsanctioned. If a model is available
through another sanctioned provider, it may still be sanctioned there. Unsanctioning the model makes
that model unsanctioned through every provider.

## What happens to unknown AI?

Observed providers and models that are not in the built-in catalog enter Authorization Queue.
Sanctioning them moves their usage to Sanctioned; unsanctioning them moves it to Unsanctioned.

## Are findings enforcement decisions?

No. Findings are evidence with a governance status. An integration may use Tally decisions as policy
input, but Tally does not claim that every unsanctioned finding must be blocked.

## Where is Native Scanner?

Native Scanner is available from Connectors. Its target, port, and authorization workflow remains
visually separate inside that page so the network-safety boundary stays explicit.

Only scan networks and systems you are authorized to test.

## Does Tally store prompts or responses?

No. Connectors may inspect bounded source fields in memory to recognize AI activity, but prompt text,
response text, documents, arbitrary request bodies, headers, cookies, and access tokens are not part
of the durable finding model. Sanitized operational attribution is retained only when the source
provides it.

## Can data be removed selectively?

Yes. Settings can remove findings, connector history, connector configurations, scanner history,
audit logs, or custom registry sanctions. A date cutoff is available for time-based records.
Deletion is permanent.

## Does the standalone API authenticate users?

Yes. Standalone Tally serves HTTPS and authenticates local email-and-password accounts. The first
registered user is an administrator; subsequent users need invitations, which grant the Member
or Administrator role. Administrators can change roles, but Tally always keeps one enabled
administrator. Sessions use secure, HttpOnly cookies that last 12 hours, and administrative
operations require the administrator role. Five failed sign-ins pause the source IP/email pair
within a 15-minute failure window; 30 failures across emails pause the source IP. An account-wide
15-minute lock remains after 50 consecutive failures across addresses. Credential requests share
a burst budget of 20 per IP, replenished at 20 per minute. Reverse proxies and shared NAT make
users share these IP limits; forwarded IP headers are not trusted. Use a trusted
certificate and the configured public origin for shared access. No nginx is required.
The in-memory throttle has a hard limit of 50,000 address and address/email entries.
At capacity, new addresses receive HTTP 429; an address whose failed sign-in cannot
be tracked is paused for 15 minutes. Cleanup runs at most once per minute and
preserves active pauses.
See [accounts and email](https://godel-labs.ai/docs/tally/accounts).
