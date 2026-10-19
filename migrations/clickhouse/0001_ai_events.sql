CREATE TABLE IF NOT EXISTS tally_ai_events (
    installation_id UUID,
    observation_id UUID,
    observed_at Int64,
    received_at Int64,
    connector_id UUID,
    connector_type LowCardinality(String),
    payload String,
    expires_at DateTime
) ENGINE = ReplacingMergeTree(received_at)
PARTITION BY toYYYYMM(fromUnixTimestamp64Milli(observed_at))
ORDER BY (installation_id, observed_at, observation_id)
TTL expires_at DELETE;

-- Derived metadata only. Retention and replay identity match tally_ai_events.
CREATE TABLE IF NOT EXISTS tally_ai_activity (
    installation_id UUID,
    observation_id UUID,
    observed_at Int64,
    received_at Int64,
    record_ids Array(UUID),
    bytes_sent Nullable(UInt64),
    bytes_received Nullable(UInt64),
    ai_request UInt8,
    expires_at DateTime,
    INDEX record_lookup record_ids TYPE bloom_filter(0.01) GRANULARITY 4
) ENGINE = ReplacingMergeTree(received_at)
PARTITION BY toYYYYMM(fromUnixTimestamp64Milli(observed_at))
ORDER BY (installation_id, observed_at, observation_id)
TTL expires_at DELETE;
