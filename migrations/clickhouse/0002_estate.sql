-- Inventory is independent of event retention. Replays and out-of-order delivery are safe:
-- first/last are commutative and metadata follows the newest observation, not the latest poll.
CREATE TABLE IF NOT EXISTS tally_estate (
    installation_id UUID,
    id UUID,
    record_type LowCardinality(String),
    first_seen SimpleAggregateFunction(min, Int64),
    last_seen SimpleAggregateFunction(max, Int64),
    detail AggregateFunction(argMax, String, Int64)
) ENGINE = AggregatingMergeTree
ORDER BY (installation_id, record_type, id);
