export type ConnectorCategoryId =
  | "ai-platforms"
  | "ai-gateways"
  | "internet-security"
  | "infrastructure";

export type ConnectorSchemaId =
  | "servicenow_agents"
  | "n8n_agents"
  | "copilot_studio_agents"
  | "langgraph_agents"
  | "dify_agents"
  | "openai_agents"
  | "claude_agents"
  | "gemini_agents"
  | "defender_stream"
  | "zscaler"
  | "palo_alto"
  | "nextdns"
  | "ai_gateway"
  | "rapid7_edr"
  | "netskope"
  | "crowdstrike_edr"
  | "casb_api"
  | "zt_gateway"
  | "aws_bedrock"
  | "aws_vpc_flow_logs"
  | "azure_vnet_flow_logs"
  | "gcp_vpc_flow_logs"
  | "gcp_vertex"
  | "azure_openai"
  | "litellm"
  | "kubernetes"
  | "microsoft_defender"
  | "cato_networks";

export interface ConnectorDefinition {
  schemaId: ConnectorSchemaId;
  title: string;
  vendorIdentifier: string;
  description: string;
  category: ConnectorCategoryId;
  connectorTypes: readonly string[];
}

export const CONNECTOR_CATEGORIES: ReadonlyArray<{
  id: ConnectorCategoryId;
  label: string;
  description: string;
}> = [
  { id: "ai-platforms", label: "AI agents & platforms", description: "Discover managed agents, AI workflows, models and deployments from cloud and application platforms." },
  {
    id: "ai-gateways",
    label: "AI gateways & proxies",
    description: "Discover model routing and policy boundaries from AI gateway control planes.",
  },
  {
    id: "internet-security",
    label: "Internet access & security",
    description: "Observe DNS, secure web gateway, firewall, EDR, CASB, and SASE signals.",
  },
  {
    id: "infrastructure",
    label: "Infrastructure discovery",
    description: "Observe cloud network flows and discover workloads or self-hosted AI runtimes on authorized scopes.",
  },
];

export const CONNECTOR_CATALOG: readonly ConnectorDefinition[] = [
  { schemaId: "gemini_agents", title: "Gemini AI Studio Managed Agents", vendorIdentifier: "gcp", description: "Discover agents saved in Google AI Studio through the Gemini Agents API.", category: "ai-platforms", connectorTypes: ["gemini_agents_api_v1"] },
  { schemaId: "claude_agents", title: "Claude Managed Agents", vendorIdentifier: "anthropic", description: "Discover saved agents, configured models and archived state from a Claude workspace.", category: "ai-platforms", connectorTypes: ["claude_agents_api_v1"] },
  { schemaId: "openai_agents", title: "OpenAI Agents", vendorIdentifier: "openai", description: "Discover saved agents and their configured models from an OpenAI project.", category: "ai-platforms", connectorTypes: ["openai_agents_api_v1"] },
  { schemaId: "servicenow_agents", title: "ServiceNow AI Agents", vendorIdentifier: "servicenow", description: "Inventory AI Agent Studio agents, active state and creator via the read-only Table API.", category: "ai-platforms", connectorTypes: ["servicenow_agents_api_v1"] },
  { schemaId: "n8n_agents", title: "n8n AI workflows", vendorIdentifier: "n8n", description: "Inventory AI agent nodes, MCP server triggers and AI workflows. Ordinary workflows are discarded.", category: "ai-platforms", connectorTypes: ["n8n_agents_api_v1"] },
  { schemaId: "copilot_studio_agents", title: "Microsoft Copilot Studio", vendorIdentifier: "copilot", description: "Inventory Copilot Studio agents and configured state from the environment's Dataverse API.", category: "ai-platforms", connectorTypes: ["copilot_studio_agents_api_v1"] },
  { schemaId: "langgraph_agents", title: "LangSmith / LangGraph agents", vendorIdentifier: "langgraph", description: "Inventory assistants and graphs from an authorized LangGraph deployment. No runs or conversation state are read.", category: "ai-platforms", connectorTypes: ["langgraph_agents_api_v1"] },
  { schemaId: "dify_agents", title: "Dify AI applications", vendorIdentifier: "dify", description: "Inventory one AI agent or workflow application per app-scoped API key. Add a connection for each application.", category: "ai-platforms", connectorTypes: ["dify_agents_api_v1"] },
  { schemaId: "defender_stream", title: "Defender event stream", vendorIdentifier: "microsoft", description: "Discover endpoint agents, parent processes and local MCP servers from Defender Streaming API events.", category: "internet-security", connectorTypes: ["microsoft_defender_stream_v1"] },
  {
    schemaId: "aws_bedrock",
    title: "AWS Bedrock & SageMaker",
    vendorIdentifier: "aws",
    description: "Discover Bedrock and SageMaker inventory plus successful Bedrock model invocations from CloudTrail.",
    category: "ai-platforms",
    connectorTypes: [
      "aws_managed_ai_inventory_api_v1",
      "aws_managed_ai_inventory_file_v1",
    ],
  },
  {
    schemaId: "aws_vpc_flow_logs",
    title: "AWS VPC Flow Logs",
    vendorIdentifier: "aws",
    description: "Read VPC network-flow metadata from a dedicated CloudWatch Logs group.",
    category: "infrastructure",
    connectorTypes: ["aws_vpc_flow_api_v1", "aws_vpc_flow_fixture_v1"],
  },
  {
    schemaId: "azure_vnet_flow_logs",
    title: "Azure VNet Flow Logs",
    vendorIdentifier: "azure",
    description: "Read virtual-network flow metadata from an Azure Log Analytics workspace.",
    category: "infrastructure",
    connectorTypes: ["azure_vnet_flow_api_v1", "azure_vnet_flow_fixture_v1"],
  },
  {
    schemaId: "gcp_vpc_flow_logs",
    title: "Google Cloud VPC Flow Logs",
    vendorIdentifier: "gcp",
    description: "Read VPC network-flow metadata from Google Cloud Logging.",
    category: "infrastructure",
    connectorTypes: ["gcp_vpc_flow_api_v1", "gcp_vpc_flow_fixture_v1"],
  },
  {
    schemaId: "azure_openai",
    title: "Azure OpenAI & Foundry",
    vendorIdentifier: "azure",
    description: "Discover Azure OpenAI and Foundry deployments plus request usage from a scoped Log Analytics workspace.",
    category: "ai-platforms",
    connectorTypes: [
      "azure_managed_ai_inventory_api_v1",
      "azure_managed_ai_inventory_file_v1",
    ],
  },
  {
    schemaId: "gcp_vertex",
    title: "Google Vertex AI",
    vendorIdentifier: "gcp",
    description: "Discover Vertex AI models and endpoints plus model invocations from scoped Data Access audit logs.",
    category: "ai-platforms",
    connectorTypes: [
      "gcp_vertex_ai_inventory_api_v1",
      "gcp_vertex_ai_inventory_file_v1",
    ],
  },
  {
    schemaId: "ai_gateway",
    title: "Cloudflare AI Gateway",
    vendorIdentifier: "cloudflare",
    description: "Discover configured providers, usage, and reported request/response sizes from Cloudflare AI Gateway. User and device attribution requires explicitly supplied custom log metadata.",
    category: "ai-gateways",
    connectorTypes: [
      "cloudflare_ai_gateway_api_v1",
      "cloudflare_ai_gateway_file_v1",
    ],
  },
  {
    schemaId: "litellm",
    title: "LiteLLM Router Gateway",
    vendorIdentifier: "litellm",
    description: "Discover model groups and capture request-level provider/model usage, assigned users, source IPs, and sanitized upstream endpoints from a LiteLLM proxy.",
    category: "ai-gateways",
    connectorTypes: [
      "litellm_model_groups_api_v1",
      "litellm_model_groups_file_v1",
    ],
  },
  {
    schemaId: "rapid7_edr",
    title: "Rapid7 EDR",
    vendorIdentifier: "rapid7",
    description: "Continuously discover AI service access from InsightIDR DNS Query logs, with source-supplied user and endpoint attribution.",
    category: "internet-security",
    connectorTypes: ["rapid7_edr_insightidr_api_v1"],
  },
  {
    schemaId: "netskope",
    title: "Netskope",
    vendorIdentifier: "netskope",
    description: "Continuously discover AI service access from Netskope page or application events, with user and device attribution when supplied.",
    category: "internet-security",
    connectorTypes: ["netskope_events_api_v1"],
  },
  {
    schemaId: "crowdstrike_edr",
    title: "CrowdStrike Falcon EDR",
    vendorIdentifier: "crowdstrike",
    description: "Discover endpoint access to registry-recognized AI services from Falcon EDR DNS telemetry, with user and endpoint attribution when supplied.",
    category: "internet-security",
    connectorTypes: ["crowdstrike_edr_ngsiem_api_v1"],
  },
  {
    schemaId: "zscaler",
    title: "Zscaler ZIA / NSS",
    vendorIdentifier: "zscaler",
    description: "Upload a Zscaler NSS JSON export from this browser. Cloud NSS is a push stream and does not expose historical event bodies through a pull API.",
    category: "internet-security",
    connectorTypes: ["zscaler_zia_nss_web_v1"],
  },
  {
    schemaId: "zt_gateway",
    title: "Cloudflare Zero Trust Gateway",
    vendorIdentifier: "cloudflare",
    description: "Pull aggregate Gateway HTTP and DNS analytics by default, with optional HTTP metadata and sent/received byte counters from network-session Logpush.",
    category: "internet-security",
    connectorTypes: ["cloudflare_zero_trust_gateway_v1"],
  },
  {
    schemaId: "nextdns",
    title: "NextDNS Live Analytics",
    vendorIdentifier: "nextdns",
    description: "Continuous DNS query stream and SaaS domain tracking.",
    category: "internet-security",
    connectorTypes: ["nextdns_logs_api_v1", "nextdns_csv_v1"],
  },
  {
    schemaId: "palo_alto",
    title: "Palo Alto Networks",
    vendorIdentifier: "palo_alto",
    description: "Upload a Palo Alto Strata HTTPS JSON export from this browser.",
    category: "internet-security",
    connectorTypes: ["palo_alto_strata_https_v1"],
  },
  {
    schemaId: "casb_api",
    title: "Cloudflare CASB",
    vendorIdentifier: "cloudflare",
    description: "Discover SaaS integrations from Cloudflare One CASB.",
    category: "internet-security",
    connectorTypes: [
      "cloudflare_casb_integrations_api_v1",
      "cloudflare_casb_integrations_file_v1",
    ],
  },
  {
    schemaId: "kubernetes",
    title: "Kubernetes Cluster Discovery",
    vendorIdentifier: "kubernetes",
    description: "Agentless read-only workload and local model discovery.",
    category: "infrastructure",
    connectorTypes: [
      "kubernetes_api_discovery_pull_v1",
      "kubernetes_api_discovery_file_v1",
    ],
  },
  {
    schemaId: "microsoft_defender",
    title: "Microsoft Defender EDR",
    vendorIdentifier: "microsoft",
    description: "Observe endpoint events and threats from Microsoft Defender for Endpoint.",
    category: "internet-security",
    connectorTypes: ["microsoft_defender_edr_api_v1"],
  },
  {
    schemaId: "cato_networks",
    title: "Cato Networks",
    vendorIdentifier: "cato_networks",
    description: "Observe network flows and security events from Cato SASE Cloud.",
    category: "internet-security",
    connectorTypes: ["cato_networks_api_v1"],
  },
];

export const NATIVE_SCANNER_DEFINITION = {
  title: "Native Scanner",
  vendorIdentifier: "tally",
  description: "Discover self-hosted AI runtimes on a network scope you are authorized to scan.",
  category: "infrastructure" as const,
};

export function getConnectorDefinitionBySchemaId(
  schemaId: ConnectorSchemaId,
): ConnectorDefinition {
  const definition = CONNECTOR_CATALOG.find((item) => item.schemaId === schemaId);
  if (!definition) throw new Error(`Unknown connector schema: ${schemaId}`);
  return definition;
}

export function getConnectorDefinitionByType(
  connectorType: string,
): ConnectorDefinition | undefined {
  return CONNECTOR_CATALOG.find((item) => item.connectorTypes.includes(connectorType));
}

export function connectorTypeLabel(connectorType: string): string {
  return getConnectorDefinitionByType(connectorType)?.title ?? humanizeConnectorType(connectorType);
}

export function connectorFriendlyName(
  connector: { friendly_name: string | null },
): string {
  return connector.friendly_name?.trim() || "Unnamed connection";
}

function humanizeConnectorType(connectorType: string): string {
  const acronyms: Record<string, string> = {
    ai: "AI",
    api: "API",
    aws: "AWS",
    casb: "CASB",
    dns: "DNS",
    gcp: "GCP",
    http: "HTTP",
    https: "HTTPS",
    nss: "NSS",
    vpc: "VPC",
    zia: "ZIA",
  };

  return connectorType
    .replace(/_v\d+$/, "")
    .split("_")
    .filter(Boolean)
    .map((part) => acronyms[part] ?? `${part.charAt(0).toUpperCase()}${part.slice(1)}`)
    .join(" ");
}

export function normalizeConnectorCategory(value: string | null | undefined): ConnectorCategoryId | undefined {
  if (value === "managed-agents" || value === "cloud-ai") return "ai-platforms";
  return CONNECTOR_CATEGORIES.find(category => category.id === value)?.id;
}
