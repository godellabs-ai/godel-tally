-- Attribution. Fresh-install schema and defaults.

CREATE TABLE destination_hosts (
    destination_host_id UUID DEFAULT gen_random_uuid() NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    CONSTRAINT destination_hosts_check CHECK ((last_seen >= first_seen)),
    CONSTRAINT destination_hosts_kind_check CHECK (kind IN ('hostname', 'ip_address')),
    CONSTRAINT destination_hosts_value_check CHECK (((length(value) >= 1) AND (length(value) <= 253))),
    CONSTRAINT destination_hosts_kind_value_key UNIQUE (kind, value),
    CONSTRAINT destination_hosts_pkey PRIMARY KEY (destination_host_id)
);

CREATE TABLE endpoint_hosts (
    endpoint_host_id UUID DEFAULT gen_random_uuid() NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    CONSTRAINT endpoint_hosts_check CHECK ((last_seen >= first_seen)),
    CONSTRAINT endpoint_hosts_kind_check CHECK (kind IN ('hostname', 'ip_address')),
    CONSTRAINT endpoint_hosts_value_check CHECK (((length(value) >= 1) AND (length(value) <= 253))),
    CONSTRAINT endpoint_hosts_kind_value_key UNIQUE (kind, value),
    CONSTRAINT endpoint_hosts_pkey PRIMARY KEY (endpoint_host_id)
);

CREATE TABLE endpoint_users (
    endpoint_user_id UUID DEFAULT gen_random_uuid() NOT NULL,
    kind TEXT DEFAULT 'email' NOT NULL,
    value TEXT NOT NULL,
    email TEXT,
    identity_key TEXT GENERATED ALWAYS AS (
CASE
    WHEN (kind = 'source_user_id') THEN value
    ELSE lower(value)
END) STORED,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    CONSTRAINT endpoint_users_check CHECK ((last_seen >= first_seen)),
    CONSTRAINT endpoint_users_email_check CHECK (((email IS NULL) OR ((length(email) >= 3) AND (length(email) <= 254)))),
    CONSTRAINT endpoint_users_kind_check CHECK (kind IN ('email', 'user_name', 'source_user_id')),
    CONSTRAINT endpoint_users_value_check CHECK (((length(value) >= 1) AND (length(value) <= 512))),
    CONSTRAINT endpoint_users_pkey PRIMARY KEY (endpoint_user_id)
);

CREATE UNIQUE INDEX endpoint_users_identity_idx ON endpoint_users (kind, identity_key);

CREATE TABLE finding_clients (
    finding_id UUID NOT NULL,
    connector_instance_id UUID NOT NULL,
    client_name TEXT DEFAULT '' NOT NULL,
    agent_id TEXT DEFAULT '' NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    CONSTRAINT finding_clients_agent_id_check CHECK (((octet_length(agent_id) <= 256) AND (agent_id !~ '[^A-Za-z0-9_.:-]'))),
    CONSTRAINT finding_clients_check CHECK (((client_name <> '') OR (agent_id <> ''))),
    CONSTRAINT finding_clients_client_name_check CHECK (client_name IN ('', 'langchain', 'langgraph', 'opencode', 'cursor', 'claude_code', 'codex', 'openai_python', 'openai_node', 'curl')),
    CONSTRAINT finding_clients_pkey PRIMARY KEY (finding_id, connector_instance_id, client_name, agent_id),
    CONSTRAINT finding_clients_connector_instance_id_fkey FOREIGN KEY (connector_instance_id) REFERENCES connector_states(connector_instance_id) ON DELETE CASCADE,
    CONSTRAINT finding_clients_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE INDEX finding_clients_connector_idx ON finding_clients (connector_instance_id);

CREATE TABLE finding_connectors (
    finding_id UUID NOT NULL,
    connector_instance_id UUID NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    CONSTRAINT finding_connectors_check CHECK ((last_seen >= first_seen)),
    CONSTRAINT finding_connectors_pkey PRIMARY KEY (finding_id, connector_instance_id),
    CONSTRAINT finding_connectors_connector_instance_id_fkey FOREIGN KEY (connector_instance_id) REFERENCES connector_states(connector_instance_id) ON DELETE CASCADE,
    CONSTRAINT finding_connectors_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE TABLE finding_destinations (
    finding_id UUID NOT NULL,
    destination_host_id UUID NOT NULL,
    port INTEGER DEFAULT 0 NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    CONSTRAINT finding_destinations_check CHECK ((last_seen >= first_seen)),
    CONSTRAINT finding_destinations_port_check CHECK (((port >= 0) AND (port <= 65535))),
    CONSTRAINT finding_destinations_pkey PRIMARY KEY (finding_id, destination_host_id, port),
    CONSTRAINT finding_destinations_destination_host_id_fkey FOREIGN KEY (destination_host_id) REFERENCES destination_hosts(destination_host_id) ON DELETE CASCADE,
    CONSTRAINT finding_destinations_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE TABLE finding_hosts (
    finding_id UUID NOT NULL,
    endpoint_host_id UUID NOT NULL,
    role TEXT NOT NULL,
    port INTEGER DEFAULT 0 NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    CONSTRAINT finding_hosts_check CHECK ((last_seen >= first_seen)),
    CONSTRAINT finding_hosts_port_check CHECK (((port >= 0) AND (port <= 65535))),
    CONSTRAINT finding_hosts_role_check CHECK (role IN ('source', 'local_service')),
    CONSTRAINT finding_hosts_pkey PRIMARY KEY (finding_id, endpoint_host_id, role, port),
    CONSTRAINT finding_hosts_endpoint_host_id_fkey FOREIGN KEY (endpoint_host_id) REFERENCES endpoint_hosts(endpoint_host_id) ON DELETE CASCADE,
    CONSTRAINT finding_hosts_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE TABLE finding_users (
    finding_id UUID NOT NULL,
    endpoint_user_id UUID NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    CONSTRAINT finding_users_check CHECK ((last_seen >= first_seen)),
    CONSTRAINT finding_users_pkey PRIMARY KEY (finding_id, endpoint_user_id),
    CONSTRAINT finding_users_endpoint_user_id_fkey FOREIGN KEY (endpoint_user_id) REFERENCES endpoint_users(endpoint_user_id) ON DELETE CASCADE,
    CONSTRAINT finding_users_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE TABLE finding_workloads (
    finding_id UUID NOT NULL,
    namespace_name TEXT NOT NULL,
    workload_name TEXT NOT NULL,
    workload_kind TEXT NOT NULL,
    runtime_image TEXT DEFAULT '' NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    CONSTRAINT finding_workloads_check CHECK ((last_seen >= first_seen)),
    CONSTRAINT finding_workloads_namespace_name_check CHECK (((length(namespace_name) >= 1) AND (length(namespace_name) <= 63))),
    CONSTRAINT finding_workloads_runtime_image_check CHECK ((length(runtime_image) <= 512)),
    CONSTRAINT finding_workloads_workload_kind_check CHECK (workload_kind IN ('deployment', 'stateful_set', 'daemon_set', 'job', 'cron_job', 'pod', 'service', 'node')),
    CONSTRAINT finding_workloads_workload_name_check CHECK (((length(workload_name) >= 1) AND (length(workload_name) <= 253))),
    CONSTRAINT finding_workloads_pkey PRIMARY KEY (finding_id, namespace_name, workload_name, workload_kind, runtime_image),
    CONSTRAINT finding_workloads_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);
