-- Correct derived attribution only. Original source revisions and usage counts remain intact.
ALTER TABLE connector_backfill_requests DROP CONSTRAINT connector_backfill_requests_source_kind_check;
ALTER TABLE connector_backfill_requests ADD CONSTRAINT connector_backfill_requests_source_kind_check
    CHECK (source_kind IN ('nextdns_api', 'cloud_flow_api', 'microsoft_defender_api'));
ALTER TABLE connector_backfill_requests DROP CONSTRAINT connector_backfill_requests_lookback_seconds_check;
ALTER TABLE connector_backfill_requests ADD CONSTRAINT connector_backfill_requests_lookback_seconds_check
    CHECK (lookback_seconds >= 60 AND lookback_seconds <=
        CASE WHEN source_kind = 'microsoft_defender_api' THEN 604800 ELSE 86400 END);

-- macOS Defender reports zero for an unavailable native process ID, shared by unrelated PIDs.
UPDATE endpoint_process_facts AS facts
SET process_key = CASE
        WHEN context #>> '{process,pid}' IS NOT NULL
         AND context #>> '{process,started_at}' IS NOT NULL
        THEN 'pid:' || (context #>> '{process,pid}') || ':' ||
             floor(extract(epoch FROM (context #>> '{process,started_at}')::timestamptz) * 1000)::bigint::text
        ELSE 'unresolved:' || observation_id::text
    END,
    context = context #- '{process,unique_id}'
FROM connector_states AS connector
WHERE connector.connector_instance_id = facts.connector_instance_id
  AND connector.connector_type IN ('microsoft_defender_edr_api_v1', 'microsoft_defender_stream_v1')
  AND context #>> '{process,unique_id}' ~ '^0+$';

UPDATE finding_activity
SET context = context #- '{process,unique_id}'
WHERE context #>> '{connector,connector_type}' IN ('microsoft_defender_edr_api_v1', 'microsoft_defender_stream_v1')
  AND context #>> '{process,unique_id}' ~ '^0+$';

-- These are unspecified addresses, not usable endpoint addresses. The raw source revisions
-- above remain available for audit; don't invent a LAN address from another connection.
UPDATE finding_activity
SET context = context #- '{actor,source_ip}'
WHERE context #>> '{connector,connector_type}' IN ('microsoft_defender_edr_api_v1', 'microsoft_defender_stream_v1')
  AND context #>> '{actor,source_ip}' IN ('0.0.0.0', '::');

UPDATE identity_facts
SET attributes = jsonb_set(attributes, '{addresses}', (attributes->'addresses') - '0.0.0.0' - '::')
WHERE attributes->>'connector_type' IN ('microsoft_defender_edr_api_v1', 'microsoft_defender_stream_v1')
  AND (attributes->'addresses' ? '0.0.0.0' OR attributes->'addresses' ? '::');

INSERT INTO identity_replay_jobs (installation_id)
SELECT DISTINCT installation_id FROM connector_states
WHERE connector_type IN ('microsoft_defender_edr_api_v1', 'microsoft_defender_stream_v1')
ON CONFLICT (installation_id) DO UPDATE
SET requested_generation = identity_replay_jobs.requested_generation + 1, updated_at = now();
