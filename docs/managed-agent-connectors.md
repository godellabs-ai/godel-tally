# Hosted managed-agent inventory

The **AI agents & platforms** connector tab includes **Gemini AI Studio Managed Agents**,
**OpenAI Agents**, and **Claude Managed Agents**. The same catalog, credential forms,
scheduler and collectors run in standalone Tally and Gate's embedded Tally.

Add a connection with a friendly name and a provider API key authorized to list the saved
agents. Keys are sealed in the existing connector credential store and are never returned
by configuration reads. Enable the provider's managed-agent API for the account first.

| Connector | Read request | Scope | Pagination |
| --- | --- | --- | --- |
| OpenAI Agents | `GET https://api.openai.com/v1/agents` with Bearer auth and `OpenAI-Beta: agents=v1` | Optional project ID in `OpenAI-Project`; otherwise the API key's project | `limit=100`, `order=asc`, `has_more` / `last_id` → `after` |
| Claude Managed Agents | `GET https://api.anthropic.com/v1/agents` with `x-api-key`, `anthropic-version: 2023-06-01`, `anthropic-beta: managed-agents-2026-04-01` | Optional workspace ID in `anthropic-workspace-id`; otherwise the key's workspace | `limit=100`, `include_archived=true`, `next_page` → `page` |
| Gemini AI Studio Managed Agents | `GET https://generativelanguage.googleapis.com/v1beta/agents` with `x-goog-api-key` | API key project; optional explicit `parent=projects/{project}/locations/{location}` | `page_size=100`, `next_page_token` → `page_token` |

Google's [managed-agent guide](https://ai.google.dev/gemini-api/docs/custom-agents#list-agents)
shows API-key listing without a parent; its [API reference](https://ai.google.dev/api/agents#ListAgents)
describes an explicit parent. The connector supports both forms. Use the project containing the
agents saved in AI Studio. This inventories saved agent definitions, not prebuilt agents,
model listings, Vertex AI deployments, or locally constructed SDK objects.

Each poll reads one bounded page and checkpoints only after admission. Further pages run
through the existing catch-up scheduler. After the last page, the next scheduled sync starts
a fresh inventory. Scope or key changes restart pagination. Different explicit scopes and
separate unscoped connections have separate agent identities; use a separate connection for
each project/workspace, and keep a connection's key in that same scope when rotating it.

Retained metadata is the pseudonymized agent identity, display name (falling back to ID),
platform, configured/archived state and a literal configured model ID when supplied. Gemini
`base_agent` is a runtime identifier, so it is not mislabeled as a model. Prompts, instructions,
descriptions, arbitrary metadata, tools, MCP credentials, environment variables, sessions and
execution data are discarded. Inventory does not imply execution or identify an executing user.
Claude archived records are labeled archived. Deleted agents absent from later polls are not
immediately deleted from Tally's historical inventory; existing retention rules apply.

Primary contracts, checked 2026-10-16:

- [OpenAI Agents overview](https://developers.openai.com/api/docs/guides/agents-api/overview) and [list agents](https://developers.openai.com/api/reference/resources/beta/subresources/agents/methods/list).
- [Claude agent setup](https://platform.claude.com/docs/en/managed-agents/agent-setup) and [list agents](https://platform.claude.com/docs/en/api/beta/agents/list).
- [Gemini Agents API](https://ai.google.dev/api/agents), [managed-agent guide](https://ai.google.dev/gemini-api/docs/custom-agents), and [agents in AI Studio](https://ai.google.dev/gemini-api/docs/aistudio-agents).

## Local verification

The fixtures under `postman/mocks/managed-agents` implement only these read contracts and
validate headers, scope and pagination. They are local fixtures derived from the linked
primary documentation. Postman's owner-mock search was unavailable without a login.
No provider keys or live provider accounts are needed.

In one terminal, from the Tally repository:

```sh
postman simulation run postman/simulations/managed-agents.sim.yaml --port 4917 --output ndjson
```

In another:

```sh
TALLY_MANAGED_AGENTS_SIM_URL=http://127.0.0.1:4917 cargo test -p tally-collector hosted_agents_postman_simulation -- --ignored
cargo test -p tally-connectors -p tally-collector -p tally-api managed_agent
```

The simulation exercises the real HTTP collectors and normalizers across two pages per provider,
empty inventories, 401/403/429/500 responses and invalid JSON. A local pass establishes compatibility
with these fixtures. Account-specific API enablement, permissions and live inventory still require
a sync with an authorized provider key.
