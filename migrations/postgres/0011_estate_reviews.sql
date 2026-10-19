-- Estate reviews. Fresh-install schema and defaults.

CREATE TABLE tally_estate_reviews (
    installation_id UUID NOT NULL,
    entity_id UUID NOT NULL,
    sanctioned BOOLEAN,
    flagged BOOLEAN DEFAULT false NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    CONSTRAINT tally_estate_reviews_pkey PRIMARY KEY (installation_id, entity_id),
    CONSTRAINT tally_estate_reviews_installation_id_fkey FOREIGN KEY (installation_id) REFERENCES installations(installation_id) ON DELETE CASCADE
);
