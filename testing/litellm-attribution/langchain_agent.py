"""Send a real LangChain/LangGraph request to a local LiteLLM gateway.

Run with the dependencies in requirements.txt and LITELLM_API_KEY set. No prompts,
responses, or credentials are printed. The default model is a free local Ollama model.
"""

import json
import os
import socket
from getpass import getuser

from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, MessagesState, StateGraph

user = os.environ.get("TALLY_TEST_USER", getuser())
agent_id = "tally-langchain-local-test"
hostname = socket.gethostname()
model = ChatOpenAI(
    model=os.environ.get("LITELLM_TEST_MODEL", "tally-smollm-135m"),
    base_url=os.environ.get("LITELLM_BASE_URL", "http://127.0.0.1:4000/v1"),
    api_key=os.environ["LITELLM_API_KEY"],
    default_headers={
        "user-agent": "LangChain-agent/1.0",
        "x-tally-source-hostname": hostname,
        "x-tally-agent-id": agent_id,
    },
    model_kwargs={"user": user},
    extra_body={
        "metadata": {
            "spend_logs_metadata": {"source_hostname": hostname, "agent_id": agent_id},
        }
    },
    max_tokens=24,
    timeout=90,
    max_retries=0,
)


def call_model(state: MessagesState):
    return {"messages": [model.invoke(state["messages"])]}


graph = StateGraph(MessagesState)
graph.add_node("assistant", call_model)
graph.add_edge(START, "assistant")
graph.add_edge("assistant", END)
result = graph.compile().invoke({"messages": [("user", "Reply with a short greeting.")]})
response = result["messages"][-1]
print(json.dumps({
    "status": "success", "user": user, "hostname": hostname,
    "declared_agent_id": agent_id, "request_id": response.response_metadata.get("id"),
    "response_id": response.id, "usage": response.usage_metadata,
}))
