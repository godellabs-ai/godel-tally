-- Run against the Gate database after the Tally dump and Gate IAM migrations.
-- The import is transactional and safe to repeat. Existing Gate accounts are
-- preserved so a post-cutover repair cannot reset a changed Gate password.
BEGIN;

DO $check$
BEGIN
    -- Accounts created by the former Tally SSO have no password until their owner sets one.
    IF EXISTS (SELECT 1 FROM tally_auth_users WHERE password_hash IS NULL) THEN
        RAISE EXCEPTION 'A Tally account has no password; send it a password link from Users before cutover; no users were imported';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM roles WHERE name = 'super_admin')
       OR NOT EXISTS (SELECT 1 FROM roles WHERE name = 'member') THEN
        RAISE EXCEPTION 'Gate IAM roles are not ready';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM tally_auth_users WHERE role = 'admin' AND disabled_at IS NULL) THEN
        RAISE EXCEPTION 'Tally has no active administrator to import';
    END IF;
    IF EXISTS (
        SELECT 1 FROM tally_auth_users
        WHERE length(email) > 255 OR length(password_hash) > 255
           OR password_hash NOT LIKE '$argon2%'
           OR length(COALESCE(NULLIF(btrim(first_name), ''),
                CASE WHEN btrim(display_name) = '' THEN split_part(email, '@', 1)
                     ELSE split_part(btrim(display_name), ' ', 1) END)) > 100
           OR length(COALESCE(NULLIF(btrim(last_name), ''),
                btrim(substr(btrim(display_name), length(split_part(btrim(display_name), ' ', 1)) + 1)))) > 100
    ) THEN
        RAISE EXCEPTION 'A Tally user has a value that Gate IAM cannot accept';
    END IF;
    IF EXISTS (
        SELECT 1 FROM tally_auth_users a
        JOIN users g ON g.id = a.user_id
        WHERE g.email <> a.email
    ) OR EXISTS (
        SELECT 1 FROM tally_auth_users a
        JOIN users g ON g.email = a.email
        WHERE g.id <> a.user_id
    ) THEN
        RAISE EXCEPTION 'A Gate account conflicts with a Tally user ID or email';
    END IF;
END
$check$;

INSERT INTO users (
    id, email, password_hash, first_name, last_name, role_id,
    is_active, created_at, updated_at
)
SELECT
    a.user_id, a.email, a.password_hash,
    COALESCE(NULLIF(btrim(a.first_name), ''),
        CASE WHEN btrim(a.display_name) = '' THEN split_part(a.email, '@', 1)
             ELSE split_part(btrim(a.display_name), ' ', 1) END),
    COALESCE(NULLIF(btrim(a.last_name), ''),
        btrim(substr(btrim(a.display_name), length(split_part(btrim(a.display_name), ' ', 1)) + 1))),
    r.id, a.disabled_at IS NULL, a.created_at, now()
FROM tally_auth_users a
JOIN roles r ON r.name = CASE a.role WHEN 'admin' THEN 'super_admin' ELSE 'member' END
ON CONFLICT (id) DO NOTHING;

DO $verify$
DECLARE source_count bigint;
DECLARE target_count bigint;
BEGIN
    SELECT count(*) INTO source_count FROM tally_auth_users;
    SELECT count(*) INTO target_count
    FROM tally_auth_users a
    JOIN users g ON g.id = a.user_id AND g.email = a.email
    JOIN roles r ON r.id = g.role_id
    WHERE r.name = CASE a.role WHEN 'admin' THEN 'super_admin' ELSE 'member' END;
    IF source_count <> target_count THEN
        RAISE EXCEPTION 'Gate IAM imported % of % Tally users', target_count, source_count;
    END IF;
    RAISE NOTICE 'Verified % Tally accounts in Gate IAM', target_count;
END
$verify$;

COMMIT;
