import type { EstateRecord } from "./estate";

/** Presentation-only identity folding. Persisted IDs and their evidence remain intact. */
export function mergeEstatePeople(nodes: EstateRecord[], edges: EstateRecord[]) {
  const groups = new Map<string, EstateRecord[]>(), aliases = new Map<string, string>();
  for (const record of nodes) if (record.detail.kind === "identity") {
    const email = record.detail.name.trim().toLowerCase();
    // Never join common display names, local usernames, redacted identities or IPs.
    const key = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? `email:${email}` : `id:${record.id}`;
    groups.set(key, [...(groups.get(key) ?? []), record]);
  }
  const people = new Map<string, EstateRecord>();
  for (const records of groups.values()) {
    const ordered = [...records].sort((a, b) => a.id.localeCompare(b.id));
    const id = ordered[0].id;
    for (const record of records) for (const alias of record.identityRecordIds ?? [record.id]) aliases.set(alias, id);
    if (records.length === 1) { people.set(id, records[0]); continue; }
    const latest = [...ordered].sort((a, b) => b.last_seen - a.last_seen)[0];
    const sources = [...new Set(records.flatMap(record => [record.detail.connector_type, ...(record.detail.evidence_sources ?? [])]))].sort();
    const same = (key: "hostname" | "source_ip") => records.every(record => record.detail[key] === latest.detail[key]) ? latest.detail[key] : null;
    people.set(id, { ...latest, id,
      identityRecordIds: [...new Set(records.flatMap(record => record.identityRecordIds ?? [record.id]))].sort(),
      first_seen: Math.min(...records.map(record => record.first_seen)), last_seen: Math.max(...records.map(record => record.last_seen)),
      teams: [...new Map(records.flatMap(record => record.teams ?? []).map(team => [team.id, team])).values()],
      flagged: records.some(record => record.flagged),
      sanctioned: records.some(record => record.sanctioned === false) ? false : records.every(record => record.sanctioned === true) ? true : null,
      detail: { ...latest.detail, name: latest.detail.name.trim().toLowerCase(), hostname: same("hostname"), source_ip: same("source_ip"), evidence_sources: sources,
        basis: `Same reported email across ${records.length} identity records. Connections and team memberships are combined; source evidence is retained.` },
    });
  }
  const emitted = new Set<string>();
  const merged = nodes.flatMap(record => {
    if (record.detail.kind !== "identity") return [record];
    const id = aliases.get(record.id) ?? record.id;
    if (emitted.has(id)) return [];
    emitted.add(id); return [people.get(id)!];
  });
  const remap = (id: string | null) => id ? aliases.get(id) ?? id : id;
  return {
    nodes: merged,
    edges: edges.map(edge => {
      const source = remap(edge.detail.source), target = remap(edge.detail.target);
      return source === edge.detail.source && target === edge.detail.target ? edge : { ...edge, detail: { ...edge.detail, source, target } };
    }),
  };
}
