-- Tally provider/model rows arrive in Gate through the complete database dump.
-- Gate also has a separate coding-agent decision for Cursor. On a fresh Gate
-- installation, carry the explicit Tally Cursor provider decision to that
-- agent while preserving any decision already made in Gate.
BEGIN;

DO $reconcile$
DECLARE
    source_decision BOOLEAN;
    previous_decision BOOLEAN;
    decision_owner TEXT;
BEGIN
    SELECT sanctioned INTO source_decision
    FROM ai_providers WHERE key = 'cursor';

    IF source_decision IS NOT NULL THEN
        SELECT sanctioned, updated_by INTO previous_decision, decision_owner
        FROM ai_agent_registry WHERE agent_key = 'cursor' FOR UPDATE;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'Gate Cursor coding-agent registry entry is missing';
        END IF;

        IF decision_owner IN ('system', 'system-default')
           AND previous_decision IS DISTINCT FROM source_decision THEN
            UPDATE ai_agent_registry
            SET sanctioned = source_decision,
                updated_at = now(),
                updated_by = 'tally-upgrade'
            WHERE agent_key = 'cursor';

            INSERT INTO ai_agent_registry_audit
                (agent_key, previous_value, sanctioned, changed_by)
            VALUES ('cursor', previous_decision, source_decision, 'tally-upgrade');
        END IF;
    END IF;
END
$reconcile$;

COMMIT;
