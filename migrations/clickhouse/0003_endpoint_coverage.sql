-- DeviceInfo contributes only a coverage denominator, never a retained non-AI log.
CREATE TABLE IF NOT EXISTS tally_endpoint_coverage (
    installation_id UUID,
    device_key String,
    last_seen SimpleAggregateFunction(max, Int64)
) ENGINE = AggregatingMergeTree ORDER BY (installation_id, device_key);
