# Rapid7 EDR and Netskope

Both connectors live in **Connectors → Internet access & security**. Standalone Tally and Gate use the same catalog, setup forms, scheduler, worker and normalization code. These are discovery connections; they do not write vendor policies or block traffic.

## Rapid7 EDR

Create an Insight platform API key with read-only Log Search access and copy the UUID of a normalized **DNS Query** log from InsightIDR. Enter the region (`us`, `us2`, `us3`, `eu`, `ca`, `au`, or `ap`), log UUID and key. DNS collection must already be configured: installing the Rapid7 endpoint agent alone does not guarantee this data source. Raw Endpoint Agent process logs are not supported.

The connector queries `GET /log_search/query/logs/{log_id}`, polls a `202` response's `Self` link, and follows completed pages' `Next` links. Links must stay on the configured regional API origin and inside the Log Search query namespace. It retains the DNS destination, reported timestamp and count, user, endpoint hostname, source IP and allow/block metadata when supplied. A deduplicated DNS log's `observation_count` remains its reported count; it is not a model invocation count.

Sources: [Rapid7 Log Search API](https://docs.rapid7.com/insightops/api/), [InsightIDR API example](https://www.rapid7.com/blog/post/2020/01/27/how-to-analyze-your-log-data-using-the-log-search-api-in-insightidr/), [normalized DNS Query fields](https://docs.rapid7.com/insightidr/keys-to-use-in-your-queries), [searchable log sets](https://docs.rapid7.com/insightidr/log-sets-you-can-search/).

## Netskope

Create a REST API v2 token with **Read** permission for `/api/v2/events/data/page` or `/api/v2/events/data/application`. Enter your commercial `https://<tenant>.goskope.com` origin, token and matching event type (`page` or `application`). Add separate connections if you need both. Other tenant domains and web transaction streaming are outside this connector's supported scope.

The connector uses `Netskope-Api-Token` and bounded `starttime`, `endtime`, `limit` and `offset` parameters. It retains event identity, time, destination hostname, user, endpoint hostname, device ID, source IP, action and reported count when supplied. Events without a usable destination are omitted. A URL becomes a hostname before it reaches the ingestion API: paths, queries, file names and arbitrary attributes are discarded.

Sources: [Netskope REST API v2 token permissions](https://docs.netskope.com/en/api-tokens-2), [Netskope-supported Splunk SOAR connector](https://github.com/splunk-soar-connectors/netskope) (v2 request and pagination contract). This integration uses time-bounded Events API reads, not the stateful dataexport iterator API.

## Polling and recovery

Initial backfill is configurable from 60 seconds through seven days, defaulting to one hour. The initial start is fixed when setup is saved, so a failed first poll does not shift the requested history forward. Reads use settled, exclusive-end windows with a five-minute delay and 500 source records per page. A checkpoint advances only after the existing ingestion pipeline durably accepts a page; retries replay stable event identities. Pages with no usable destination still advance their source checkpoint. API errors and malformed pages leave the checkpoint unchanged and use the worker's normal retry schedule. An interrupted long-running Rapid7 query is restarted from its last durable page, not from a transient polling URL.

The delay is an ingestion settling allowance, not a guarantee that arbitrarily late vendor events will be recovered. Source retention, permissions, vendor rate limits and available telemetry constrain coverage. Neither DNS nor web access proves that a model was invoked. API keys and tenant/log configuration are stored in the existing encrypted credential bundle; configuration edits can retain saved keys by leaving them blank.

## Local verification

The Postman simulation uses fixtures derived from the linked vendor contracts; it is not evidence from a live customer tenant. It covers Rapid7 asynchronous polling and pagination, Netskope pagination, metadata redaction, and upstream 401/429/503 failures.

```sh
postman simulation run postman/simulations/security-logs.sim.yaml --port 4909 --output ndjson
TALLY_SECURITY_SIM_URL=http://127.0.0.1:4909 cargo test -p tally-collector --lib security_logs_http_simulation -- --ignored
cargo test -p tally-connectors -p tally-api -p tally-collector --lib security_logs
```

Actual tenant credentials and live vendor compatibility still need deployment verification.
