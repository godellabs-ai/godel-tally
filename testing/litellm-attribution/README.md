# Real local LiteLLM attribution test

This test sends a real LangChain/LangGraph workflow request through LiteLLM to a free local
Ollama model. It does not generate mocked responses, synthetic employees, or demo findings.

The laptop already has a loopback-only gateway at `http://127.0.0.1:4000`, a PostgreSQL spend-log
database, and Ollama at `http://127.0.0.1:11434`. The existing `tally-smollm-135m` route targets
`ollama_chat/smollm2:135m`. The Tally connector named **LiteLLM — seven free local models** polls it.
No cloud infrastructure or paid model is needed.

Verified with LiteLLM **1.104.0**: real requests to both `smollm2:135m` and
`deepseek-r1:1.5b` retained the supplied user, source hostname and agent ID, plus the LangChain
user-agent in the source API. Tally extracted the bounded attribution and discarded the raw
user-agent. To repeat with DeepSeek R1, set `LITELLM_TEST_MODEL=tally-deepseek-r1-15b`.

## Repeat a real request

```sh
# uv is already installed on this laptop. For another laptop: brew install uv
uv venv --python 3.12 .local/connector-population/langchain-venv
uv pip install --python .local/connector-population/langchain-venv/bin/python \
  -r testing/litellm-attribution/requirements.txt

# Set LITELLM_API_KEY privately to the local gateway key; never paste it into an artifact.
export TALLY_TEST_USER='your-email@example.com'
.local/connector-population/langchain-venv/bin/python \
  testing/litellm-attribution/langchain_agent.py
```

The script reports a request ID and token counts, not response text or credentials. It supplies
its actual laptop hostname, an explicit local test agent ID, and a LangChain client header. The
API can retain these in `metadata.spend_logs_metadata`, `metadata.user_agent`, and `request_tags`;
which fields are available depends on LiteLLM's version and configuration. Do not mistake a
`localhost:4000` proxy host header for a source IP. In this Docker setup the source-native
requester IP is the bridge/NAT address, not the laptop LAN or public address.

After at least five minutes, sync the connector. Search Tally Findings for `LangChain`, the email,
or `tally-langchain-local-test`, and inspect Users, Endpoints, Destinations, Sources, and
Clients / frameworks. If the cursor already passed the request, use a bounded connector backfill.
The displayed framework and agent ID are source-reported hints, not authenticated agent-process
discovery. Tally does not retain raw headers, user-agent text, request tags, or model content.

No images are built and no existing services need to be restarted for this test. The existing
local containers and model volume are left running for repeat testing.
