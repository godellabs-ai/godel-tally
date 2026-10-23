-- Invitations carry the role they grant and can be listed and revoked by administrators.

ALTER TABLE tally_auth_invitations
    ADD COLUMN invitation_id UUID DEFAULT gen_random_uuid() NOT NULL,
    ADD COLUMN role TEXT DEFAULT 'member' NOT NULL,
    ADD COLUMN created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    ADD COLUMN revoked_at TIMESTAMPTZ,
    ADD CONSTRAINT tally_auth_invitations_role_check CHECK (role IN ('admin', 'member')),
    ADD CONSTRAINT tally_auth_invitations_id_key UNIQUE (invitation_id);

CREATE INDEX tally_auth_invitations_pending_idx ON tally_auth_invitations (email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
