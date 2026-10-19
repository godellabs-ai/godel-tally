const INTERNAL_DATABASE_SOURCE_RE =
  /(^|[^a-z0-9])(clickhouse|postgres|postgresql|pg|mysql|mariadb|sqlite|mongo|mongodb|rds)([^a-z0-9]|$)/;
const INTERNAL_FILE_SOURCE_RE =
  /(^|[^a-z0-9])(seaweed|seaweedfs|s3|minio|object[-_\s]*storage|blob[-_\s]*storage|file[-_\s]*server)([^a-z0-9]|$)/;

export function sourceDisplayName(name: string): string {
  const normalized = name.trim().toLowerCase();
  if (!normalized) return name;
  if (INTERNAL_DATABASE_SOURCE_RE.test(normalized)) return "Database";
  if (INTERNAL_FILE_SOURCE_RE.test(normalized)) return "File Server";
  return name;
}

/** Wire AI Registry outcome → overview label. */
export const authorizationStatusDisplayName = (status: string): string => {
  const s = (status || "").trim().toLowerCase();
  if (s === "sanctioned") return "Sanctioned";
  if (s === "unsanctioned") return "Unsanctioned";
  return "Review";
};

/** Raw wire verdict → the display name used for node ids ("system" stays as-is). */
export const verdictDisplayName = (verdict: string): string => {
  const v = verdict || "Unknown Verdict";
  if (v === "allow" || v === "pass") return "allowed";
  if (v === "warn") return "warned";
  if (v === "block") return "blocked";
  return v;
};

export function hasReportedDecision(verdict: string | null | undefined) {
  const value = verdict?.trim().toLowerCase();
  return Boolean(value && value !== "unknown" && value !== "unknown verdict");
}
