# Tally product usage

This guide covers the standalone Tally operator console. Start Tally with `make run`, then open the
URL shown by the command. The default is <http://127.0.0.1:8080>.

The standalone console has no built-in user authentication or TLS. Keep it on loopback for local
use. Before sharing it, place it behind an authenticating TLS reverse proxy and restrict network
access.

## Product workflow

Tally follows a simple operating loop:

1. Configure one or more discovery sources under **Connectors**.
2. Let the collector synchronize them, or request an immediate sync.
3. Review observed usage under **Findings**.
4. Decide whether previously unknown providers and models are sanctioned.
5. Use **AI Registry** to review or change broader provider and model decisions.
6. Review operational changes under **Audit logs**.

Tally findings are evidence. A sanctioned or unsanctioned status is a governance classification; it
does not by itself change a vendor policy or block traffic.

## Configure connectors

Open **Connectors** and choose a category:

- **Cloud AI platforms** includes AWS Bedrock and SageMaker, Azure OpenAI and Foundry, and Google
  Vertex AI.
- **Managed AI agents** includes ServiceNow AI Agents and n8n AI workflows.
- **AI gateways & proxies** includes Cloudflare AI Gateway and LiteLLM.
- **Internet access & security** includes DNS, secure web gateway, firewall, CASB, EDR, and SASE
  sources.
- **Infrastructure discovery** includes cloud network flows, Kubernetes discovery, and Native
  Scanner.

Select a connector card to configure it. The dialog shows the exact read-only permissions and
fields required by that source.

1. Give the connection a unique **Friendly Name**. This name appears on findings and makes multiple
   accounts, regions, or environments distinguishable.
2. Create the least-privilege credentials listed in **Required Read-Only Permissions**.
3. Enter the requested account, project, region, workspace, endpoint, or scope identifiers.
4. For sources that support it, choose between explicit credentials and the collector VM's service
   account or workload identity.
5. Keep the initial backfill window and record limit bounded. Smaller initial windows are easier to
   validate and do not prevent later cursor-based synchronization.
6. Save the connector. Credentials are encrypted with the installation's `TALLY_SECRET_KEY` before
   PostgreSQL persistence and are never returned by the API.

The collector normally picks up a saved configuration within a minute. Use **Sync** on a configured
connection or **Sync All Feeds** to make schedules due immediately. The collector claims the work
on its next poll, so a requested sync may take several seconds to appear.

### LiteLLM request attribution

The native LiteLLM connector reads `/model_group/info` and the database-backed `/spend/logs/v2`
API. A custom callback JSONL file is a different source and is not automatically read. Enable
LiteLLM spend logging and give the connector a key authorized to read both endpoints.

Before discarding source material, Tally extracts the request's end user (or source-native user
identity), validated requester IP, provider/model, upstream destination host/port, and a recognized
client/framework label such as LangChain. It also retains an explicit agent ID and source hostname
when those are available in the API's allowlisted attribution metadata. A hostname must be
explicitly reported: the proxy's `Host` header is not the requesting laptop, and arbitrary
`X-Forwarded-For` headers are not promoted to source IPs.

Clients can send `metadata.spend_logs_metadata.source_hostname` and
`metadata.spend_logs_metadata.agent_id`; availability depends on the LiteLLM version and
configuration. Tally also handles these explicit fields in request context and
`x-tally-source-hostname` / `x-tally-agent-id` headers **when exposed by the source API**. It does not
store these raw header collections. Raw user-agent strings are reduced to allowlisted names;
prompts, responses, credentials, costs, token counts, other tags and arbitrary metadata are
discarded before durable ingestion.

Open a finding's **Clients / frameworks** section or search for `LangChain` or an explicit agent
ID. Findings remain grouped by provider/model: client hints do not create fictitious agent
inventory entries or extra model invocations. Existing findings need a bounded backfill to gain
new attribution; it cannot be recovered from headers Tally previously discarded. Native polling
allows five minutes for source log settlement before importing a request.

### Edit or remove a connector

Open a configured connector card to edit it. Existing secret values are not displayed; leave a
secret field blank to retain its saved value. Check the card and recent run information for errors
after changing permissions or scope.

Deleting a connector removes its configuration, schedule, and sync receipts. Existing findings are
retained, but the deleted connector is no longer linked to them. Use **Settings** when the findings
must also be removed.

### Browser-upload connectors

Defender Streaming API envelopes, Zscaler NSS and Palo Alto Strata exports are uploaded from the browser instead of read from a host
filesystem path. Choose an authorized JSON or NDJSON export, preview it, review the canonical
digest and result counts, explicitly authorize that preview, and then commit it. Tally normalizes
the source in memory and does not retain the uploaded source file.

### Native Scanner

Native Scanner is available under **Infrastructure discovery**. Enter only a network scope you are
authorized to scan. Review the canonical target and port plan before acknowledging authorization
and starting the scan. Scanner results are resource-discovery evidence; finding an open service is
not counted as a model invocation.

## Review findings

Open **Findings** and choose a view:

- **Authorization Queue** contains observed providers or models without a governance decision.
- **Unsanctioned** contains findings whose provider or global model decision is unsanctioned.
- **Sanctioned** contains observed usage whose applicable decisions are sanctioned.

Search matches provider and model names, model versions, endpoint and destination values, user
identities, and source connector names. Select rows in Authorization Queue to sanction or
unsanction several findings at once, or use the decision buttons on an individual row.

Open a row to inspect:

- whether the evidence represents an AI request, network activity, or resource discovery;
- first and most recent observation times and the usage count;
- source devices or local service endpoints;
- remote destinations and ports;
- user identities;
- source connectors; and
- the reason an item is unsanctioned.

Attribution is source-dependent. An empty user, endpoint, destination, or workload section means
the observing source did not provide that field; it does not prove that no such identity exists.

## Manage the AI Registry

Open **AI Registry** to browse providers by category or switch to **AI Models**. Search, filter by
sanction status, filter models by capability, and apply decisions individually or in bulk.

Provider and model decisions have different scopes:

- A provider decision applies to usage routed through that provider.
- A model decision is global and applies wherever that model is available.
- An undecided provider or model remains in Authorization Queue after it is observed.

For example, unsanctioning a provider does not automatically unsanction the same model through a
different provider. Unsanctioning the model does make that model unsanctioned through every route.

## AI inventory, audit, and data removal

**Overview** is the homepage, with **Estate map** first and **Inventory** second. Select an entity
for its first/last-seen times, attribution basis, relationships and activity summaries. Search,
source, type and recency filters cover loaded records; load additional pages when the page indicates more inventory is available. The coverage
statement distinguishes endpoint visibility from unknown enterprise-wide coverage. Configured agents
prove declared inventory, and provider sanctions do not automatically sanction their agents.

AI logs expire after 90 days by default; inventory remains until explicitly removed. Settings offers
separate AI-log and inventory deletion scopes. See [AI estate](ai-estate.md) for migration, retention,
Defender streaming setup and managed-agent permissions.

**Audit logs** record connector operations, governance changes, scans, imports, and data-removal
operations. Use connector run status and audit history together when diagnosing missing or stale
findings.

**Settings** shows stored-data counts and supports scoped deletion of findings, connector history,
connector configurations, scanner history, audit logs, and changed registry sanctions. Some scopes
accept a date cutoff. Deletion requires the displayed confirmation phrase and cannot be undone.

## Health and API access

Check readiness through the same public origin as the console:

```bash
curl --fail http://127.0.0.1:8080/api/v1/tally/health/ready
```

Use `docker compose -f docker-compose.yml logs -f collector` to inspect connector-worker failures
and `docker compose -f docker-compose.yml logs -f tallyd` for API or database failures. The complete
HTTP contract is available in [OpenAPI](../specs/openapi.json).


## Accounts and password recovery

The first registered account is the administrator. Additional accounts require an invitation
issued from **Users**. Accounts use email and password; existing accounts without a password
can set one using an administrator-issued reset link. Tally no longer supports SSO.

Choose **Forgot password?** on the sign-in page. When email delivery is configured, Tally sends a
single-use link valid for one hour. Resetting a password revokes that account's existing sessions.
Changing a password while signed in also invalidates outstanding reset links and other sessions.
A failed sign-in or registration attempt ends any previous session presented by that browser.

Administrators configure **Settings → Email delivery** with SMTP, AWS SES, Resend, SendGrid,
Mailgun or Postmark. Save the settings, then use **Send test** to check delivery. Provider secrets
are encrypted with `TALLY_SECRET_KEY`; keep that key stable. Blank secret fields retain the saved
credential for the same provider. Saved settings override environment variables; disabling
email here also disables environment-configured delivery. Set `TALLY_URL` to the public console
address: emailed reset links always use that address, never the incoming request's Host header.
SES can use explicit access keys or the server's AWS credential chain. Provider-side sender
verification and recipient restrictions still apply.

Without email, an administrator can issue a link from **Users** and share it privately. If all
administrators are locked out, the operator can configure delivery using the environment variables
in `.env.example` and restart Tally. If saved settings explicitly disable email, an operator must
repair that configuration or the account in PostgreSQL after backing up the database. A full
database reset is a last resort because it deletes Tally data and accounts; the first newly
registered account becomes administrator. Tally never resets the database automatically.

## Explore an evaluation workspace

Administrators can select **Add evaluation data** on an empty Overview, or use **Settings → Evaluation
workspace** at any time. The examples cover every connector in the catalog and its supported
transport variants, all four connector categories, all twelve normalized event types, all six
provider categories, and sanctioned/unsanctioned registry defaults. They also populate findings,
people, devices, destinations, workloads, models, agent/MCP relationships, connector runs, ingestion receipts,
scanner history, audit history, and inventory reviews.

The dataset uses real provider and model names, including OpenAI, Anthropic, Google, Amazon
Bedrock, GPT-4o, Claude Sonnet 4, Gemini 2.5 Pro, and Llama 3.3. People, private enterprise
egress destinations, applications, and activity are fictional. Records use normal product and
workload names; Settings identifies the evaluation dataset. Connectors are paused, with no
credentials or scheduled jobs. Add a separate connection for a live source.
Evaluation providers follow the enterprise exceptions in the [registry defaults](data-model.md#catalog-and-governance);
models follow their catalogued owner's default, including when hosted through another provider.
Other providers and models start unsanctioned. SaaS examples use the same provider decisions.
Evaluation providers, models, and attribution use a separate namespace; existing registry decisions and
operational records are preserved. Repeating **Restore evaluation data** repairs missing examples
without duplicating them. Existing decisions on evaluation records are retained.

To remove the examples, choose **Remove evaluation data…**, review the counts, and type
`delete evaluation data` in the confirmation dialog. The server selects records from the workspace's
persisted ownership manifest. A partial failure remains retryable; finish removal before adding a
new workspace. To replace an older dataset with the current names and sanction defaults, remove it
and add evaluation data again. This control is independent of general operational deletion.

## Preview and delete operational data

In standalone Tally, open **Settings → Data deletion**. In Gate, open **Admin → Data → Tally data**.
Both use the same component and flow:

1. **Build deletion target:** choose categories and optionally an older-than date.
2. **Preview:** inspect the affected record counts. Changing the target clears the old preview.
3. **Delete…:** refresh the preview and type `delete` in the confirmation dialog.

**Delete All…** selects all operational categories across all time and requires `delete all`.
Deleting connector configurations also deletes their run history and ingestion receipts.
Connector configurations and provider/model sanction resets are not date-filtered; inventory
reviews and timestamped records honor the cutoff. New ingestion may change counts after a preview.
The installation identity, accounts, and built-in AI catalog remain. If operational deletion removes
part of the evaluation workspace, Settings still offers its repair or complete removal.

The APIs are `GET/POST /api/v1/tally/data/sample`, `POST /api/v1/tally/data/sample/delete`, and
`POST /api/v1/tally/data/preview`. Standalone requires an administrator. Gate requires
`tally_data:delete`. See [OpenAPI](../specs/openapi.json) for request and response schemas.
