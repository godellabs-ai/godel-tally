import type { EventFindingContext, EventStreamResponse } from "../../lib/event-stream";

export function eventStreamFixture(params = new URLSearchParams()): EventStreamResponse {
  let items = Array.from({ length: 265 }, (_, index) => ({
    observation_id: `00000000-0000-0000-0000-${String(index + 1).padStart(12, "0")}`,
    observed_at: new Date(Date.UTC(2026, 9, 16, 10, 0, index)).toISOString(),
    received_at: "2026-10-16T10:06:00.000Z", kind: "http_metadata",
    connector: { instance_id: "source-one", connector_type: "gateway" },
    actor: { source_ip: index % 2 === 0 ? "10.20.1.41" : "10.20.1.42", request_client: { name: "cursor" }, hostname: index % 2 === 0 ? "laptop-even" : "laptop-odd", identity: { email: "alice@example.test" } },
    destination: { host: "api.example.test" }, service: { ai_request: true, declared_model_id: "same-model" }, outcome: { result: "allowed" },
  }));
  const status = params.get("status");
  if (status && status !== "all") items = items.filter(item => ["unsanctioned", "authorization_queue", "sanctioned"][(Number(item.observation_id.slice(-12)) - 1) % 3] === status);
  if (params.get("q")) items = items.filter(item => JSON.stringify(item).includes(params.get("q")!));
  if (params.get("kind")) items = items.filter(item => item.kind === params.get("kind"));
  if (params.get("outcome")) items = items.filter(item => item.outcome.result.includes(params.get("outcome")!));
  if (params.get("sort") !== "oldest") items.reverse();
  const size = Number(params.get("page_size") ?? 100), total = items.length;
  const pages = Math.max(1, Math.ceil(total / size)), page = Math.min(pages, Number(params.get("page") ?? 1));
  const visible = items.slice((page - 1) * size, page * size);
  const findings: EventFindingContext[] = visible.map(event => {
    const index = (Number(event.observation_id.slice(-12)) - 1) % 3;
    return { observation_id: event.observation_id, finding_id: `finding-${event.observation_id}`, evidence_kind: "ai_usage",
      status: (["unsanctioned", "authorization_queue", "sanctioned"] as const)[index],
      provider: { id: `provider-${index}`, key: "example-ai", name: "Example AI", sanctioned: index === 0 ? false : index === 1 ? null : true },
      model: { id: "same-model", key: "same-model", name: "same-model", sanctioned: true }, model_version: null };
  });
  return { items: visible, findings, total, page, page_size: size, total_pages: pages,
    snapshot: Number(params.get("snapshot") ?? 1792145000000), sources: [{ connector_id: "source-one", label: "Company gateway" }] };
}
