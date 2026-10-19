import assert from "node:assert/strict";
import { test } from "node:test";
import { sourceModule } from "./source-module.mjs";

// Exercise the actual TypeScript map algorithms without starting Next.js.
const record = (id, kind, platform = null) => ({ id, record_type: "node", first_seen: 1, last_seen: 2, detail: { kind, name: id, platform, connector_type: "godel_gate_runtime" } });
const { connectorEventFlow, combineEventFlows, findingsEventFlow } = sourceModule("lib/estate-event-flow.ts");

test("overview includes all saved finding statuses without requiring an agent or estate record", () => {
  const finding = status => ({ finding_id: status, status, provider: { name: "Provider" }, model: { name: "Model" }, users: [] });
  const data = { sanctioned: [finding("sanctioned")], unsanctioned: [finding("unsanctioned")], authorization_queue: [finding("authorization_queue")] };
  const flow = findingsEventFlow(data);
  assert.deepEqual(flow.paths.map(path => path.authorization_status), ["sanctioned", "unsanctioned", "authorization_queue"]);
  assert(flow.paths.every(path => path.evidence === "finding" && path.agent === "" && path.user === "" && path.verdict === "Unknown"));
  assert.equal(flow.events, 0);
  assert.equal(scopeEventPaths(flow.paths, { ...defaultFlowScope, lens: "unsanctioned" }).length, 1);
  assert.equal(scopeEventPaths(flow.paths, { ...defaultFlowScope, lens: "review" }).length, 1);
  // A decision refresh moves the existing finding rather than leaving a stale graph node.
  const moved = { ...data.unsanctioned[0], status: "sanctioned" };
  const refreshed = findingsEventFlow({ ...data, unsanctioned: [], sanctioned: [...data.sanctioned, moved] });
  assert.equal(refreshed.paths.filter(path => path.authorization_status === "unsanctioned").length, 0);
  assert.equal(refreshed.paths.filter(path => path.authorization_status === "sanctioned").length, 2);
});

test("finding graph deduplicates users and findings without pairing aggregated actors or destinations", () => {
  const row = { finding_id: "one", status: "sanctioned", provider: { name: "Provider" }, model: null,
    users: [{ kind: "email", value: " ALICE@example.com " }, { kind: "email", value: "alice@example.com" }, { kind: "user_name", value: "bob" }],
    clients: [{ agent_id: "private-agent" }], destinations: [{ value: "private.example.com" }] };
  const flow = findingsEventFlow({ sanctioned: [row, row], unsanctioned: [], authorization_queue: [] });
  assert.equal(flow.paths.length, 2);
  assert.deepEqual(flow.paths.map(path => path.user), ["alice@example.com", "bob"]);
  assert(flow.paths.every(path => path.findingId === "one" && path.agent === "" && path.source === "Provider"));
});
function connectorFlowFixture() {
  const people = [record("alice@example.com", "identity"), record("bob@example.com", "identity")];
  const actors = [...people, record("alice-device", "device"), record("bob-device", "device"), record("Claude Code", "agent", "coding_agent"), record("IT assistant", "agent", "servicenow"), record("GitHub MCP", "mcp_server"), record("api.example.com", "endpoint"), record("managed-orphan", "workflow"), record("Gate-only", "agent")];
  actors.forEach(node => { if (node.id !== "Gate-only") node.detail.connector_type = "microsoft_defender_stream_v1"; });
  const connections = [[people[0].id, "alice-device"], [people[1].id, "bob-device"], ["alice-device", "Claude Code"], ["bob-device", "IT assistant"], ["Claude Code", "GitHub MCP"], ["IT assistant", "api.example.com"]]
    .map(([source, target], i) => ({ ...record(`connector-link-${i}`, "calls"), record_type: "edge", detail: { kind: "calls", source, target, connector_type: "microsoft_defender_stream_v1" } }));
  connections.push({ ...record("runtime-mirror", "runs"), record_type: "edge", detail: { kind: "runs", source: people[0].id, target: "Gate-only", connector_type: "godel_gate_runtime" } });
  return { actors, connections };
}

test("connector Data flow retains managed inventory, exact callers and destinations with unknown enforcement", () => {
  const { actors, connections } = connectorFlowFixture();
  const flow = connectorEventFlow(actors, connections);
  assert.equal(flow.events, 0);
  assert.deepEqual(flow.verdicts, []);
  assert.equal(flow.paths.length, 3);
  assert(flow.paths.every(path => path.evidence === "connector" && path.domain === "Unknown" && path.verdict === "Unknown"));
  assert.deepEqual(flow.paths.filter(path => path.user === "alice@example.com").map(path => [path.agent, path.source]), [["Claude Code", "GitHub MCP"]]);
  assert.deepEqual(flow.paths.filter(path => path.user === "bob@example.com").map(path => [path.agent, path.source]), [["IT assistant", "api.example.com"]]);
  assert(flow.paths.some(path => path.agent === "managed-orphan" && path.user === "" && path.source === "Unknown"));
  assert(!flow.paths.some(path => path.agent === "Gate-only"));
});

test("connector paths do not guess an agent from network-only evidence or use dangling endpoints", () => {
  const { actors, connections } = connectorFlowFixture();
  const network = { ...connections[0], id: "network", detail: { ...connections[0].detail, source: "alice-device", target: "api.example.com" } };
  const flow = connectorEventFlow(actors.slice(0, 4).concat(actors.find(node => node.id === "api.example.com")), [connections[0], network]);
  assert.equal(flow.paths.length, 1);
  assert.equal(flow.paths[0].user, "alice@example.com");
  assert.equal(flow.paths[0].agent, "");
  assert.equal(flow.paths[0].source, "api.example.com");
  assert.equal(connectorEventFlow(actors.slice(0, 4), [network]).paths.length, 0);
});

test("connector paths deduplicate loaded records and never convert policy status to allowed decisions", () => {
  const { actors, connections } = connectorFlowFixture();
  actors.find(node => node.id === "Claude Code").sanctioned = true;
  const flow = connectorEventFlow([...actors, ...actors], [...connections, ...connections]);
  assert.equal(flow.paths.length, 3);
  const coding = flow.paths.find(path => path.agent === "Claude Code");
  assert.equal(coding.authorization_status, "sanctioned");
  assert.equal(coding.verdict, "Unknown");
  assert.equal(connectorEventFlow(actors, connections, 1).truncated, true);
  assert.equal(connectorEventFlow(actors, connections, 1).paths.length, 1);
});

test("Gate and Tally flow composition preserves exact event totals and combines known product names", () => {
  const { actors, connections } = connectorFlowFixture();
  const connectors = connectorEventFlow(actors, connections);
  const runtime = { events: 7, verdicts: [{ key: "block", count: 7 }], truncated: false, paths: [{ user: "alice@example.com", agent: "claude-code", source: "github", domain: "Engineering", verdict: "block", authorization_status: "sanctioned", count: 7 }] };
  const combined = combineEventFlows(runtime, connectors, name => name === "claude-code" ? "Claude Code" : name);
  assert.equal(combined.events, 7);
  assert.deepEqual(combined.verdicts, runtime.verdicts);
  assert.equal(combined.paths.length, 4);
  assert.equal(combined.paths.find(path => path.evidence === "connector" && path.user === "alice@example.com").agent, "claude-code");
  assert.equal(combineEventFlows(null, connectors).paths.length, 3);
  assert.equal(combineEventFlows(runtime, { ...connectors, paths: [], truncated: true }).truncated, true);
});

test("connector child-agent paths retain the parent's caller without assigning the child's tools to it", () => {
  const { actors, connections } = connectorFlowFixture();
  const parent = { ...record("workflow", "workflow"), detail: { kind: "workflow", name: "workflow", connector_type: "n8n_agents_api_v1" } };
  connections.find(edge => edge.detail.target === "Claude Code").detail.target = parent.id;
  connections.push({ ...connections[0], id: "child-call", detail: { ...connections[0].detail, source: parent.id, target: "Claude Code", kind: "calls" } });
  const flow = connectorEventFlow([...actors, parent], connections);
  assert(flow.paths.some(path => path.agent === "workflow" && path.user === "alice@example.com" && path.source === "Unknown"));
  assert(!flow.paths.some(path => path.agent === "workflow" && path.source === "GitHub MCP"));
  assert(flow.paths.some(path => path.agent === "Claude Code" && path.user === "alice@example.com" && path.source === "GitHub MCP"));
});

const { defaultFlowScope, scopeEventPaths, selectEventPaths, inventoryForEventPaths } = sourceModule("lib/estate-flow-selection.ts");
test("overview selection uses OR within a column and AND across complete paths", () => {
  const paths = [
    { user: "alice", agent: "a", source: "one", authorization_status: "sanctioned", domain: "Finance", verdict: "block", count: 2 },
    { user: "bob", agent: "a", source: "two", authorization_status: "sanctioned", domain: "Engineering", verdict: "pass", count: 1 },
    { user: "alice", agent: "b", source: "three", authorization_status: "unsanctioned", domain: "Engineering", verdict: "warn", count: 1 },
  ];
  assert.deepEqual(selectEventPaths(paths, ["Agent:a", "Agent:b", "User:alice"]), [paths[0], paths[2]]);
  assert.deepEqual(selectEventPaths(paths, ["User:alice", "Source:two"]), []);
  assert.deepEqual(selectEventPaths(paths, ["Taxonomy:Finance", "Verdict:blocked"]), [paths[0]]);
});

test("inventory follows exact selected connector IDs, including original identity receipts", () => {
  const { actors, connections } = connectorFlowFixture();
  const duplicate = { ...actors[0], id: "second-alice", detail: { ...actors[0].detail, name: " ALICE@EXAMPLE.COM " } };
  const unrelated = { ...actors.find(node => node.id === "Claude Code"), id: "another-install" };
  const nodes = [...actors, duplicate, unrelated];
  const flow = connectorEventFlow(nodes, connections);
  const paths = selectEventPaths(flow.paths, ["User:alice@example.com", "Source:GitHub MCP"]);
  const ids = inventoryForEventPaths(nodes, paths).map(record => record.id);
  assert.deepEqual(new Set(ids), new Set(["alice@example.com", "second-alice", "alice-device", "Claude Code", "GitHub MCP"]));
  assert(!ids.includes("another-install"));
  assert.deepEqual(inventoryForEventPaths(nodes, []), []);
});

test("risk lenses require explicit evidence and distinguish Gate events from connector discoveries", () => {
  const { actors, connections } = connectorFlowFixture();
  const device = actors.find(node => node.id === "alice-device");
  device.protection = { state: "unknown", collectors: [] };
  actors.find(node => node.id === "IT assistant").sanctioned = false;
  let flow = connectorEventFlow(actors, connections);
  assert.equal(scopeEventPaths(flow.paths, { ...defaultFlowScope, lens: "exposure", risk: "unprotected" }).length, 0);
  assert(scopeEventPaths(flow.paths, { ...defaultFlowScope, lens: "exposure" }).every(path => path.agent === "IT assistant"));
  device.protection = { state: "protected", collectors: ["ggate"], liveness: "offline" };
  flow = connectorEventFlow(actors, connections);
  assert.equal(scopeEventPaths(flow.paths, { ...defaultFlowScope, lens: "protected" }).length, 1);
  assert.equal(scopeEventPaths(flow.paths, { ...defaultFlowScope, lens: "exposure", risk: "offline" }).length, 1);
  assert.equal(scopeEventPaths(flow.paths, { ...defaultFlowScope, lens: "exposure", risk: "unprotected" }).length, 0);
  const event = { ...flow.paths[0], evidence: undefined, verdict: "block", risks: [], protected: undefined };
  assert.deepEqual(scopeEventPaths([...flow.paths, event], { ...defaultFlowScope, source: "runtime", lens: "exposure", risk: "blocked" }), [event]);
});
