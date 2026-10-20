import * as React from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  AlertCircle,
  Eye,
  EyeOff,
  KeyRound,
  Plus,
  RefreshCw,
  Server,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import {
  tallyFetch,
  scheduleConnector,
  type TallyMutationResult,
  type ConnectorJob,
  type ConnectorState,
  type ConnectorSyncResponse,
  type ImportAdapter,
  type ImportCommitResponse,
  type ImportPreviewResponse,
} from "../lib/tally";
import {
  getConnectorDefinitionBySchemaId,
  type ConnectorDefinition,
  type ConnectorSchemaId,
} from "../lib/connector-catalog";
import { VendorBadge, getVendorFromIdentifier } from "./vendor-icon";
import { cn } from "@/lib/utils";

export type ConnectorSchemaField = {
  name: string;
  label: string;
  type: "text" | "number" | "secret" | "file";
  defaultValue?: string | number;
  min?: number;
  max?: number;
  help?: string;
  placeholder?: string;
  optional?: boolean;
  hidden?: boolean;
  accept?: string;
  maxBytes?: number;
  section?: string;
};

export type ConnectorSchema = ConnectorDefinition & {
  source_kind: string;
  adapter?: string;
  permissions: string[];
  fields: ConnectorSchemaField[];
  uploadAdapter?: ImportAdapter;
  authentication?: {
    credentialFields: string[];
    credentialLabel: string;
    collectorIdentityLabel: string;
    collectorIdentityHelp: string;
  };
};

export const CONNECTOR_SCHEMAS: Record<ConnectorSchemaId, ConnectorSchema> = {
  gemini_agents: {
    ...getConnectorDefinitionBySchemaId("gemini_agents"),
    source_kind: "managed_agents",
    permissions: ["Gemini API key for the project containing your saved agents, with Managed Agents access enabled."],
    fields: [
      { name: "platform", label: "Platform", type: "text", defaultValue: "gemini", hidden: true },
      { name: "base_url", label: "API origin", type: "text", defaultValue: "https://generativelanguage.googleapis.com", hidden: true },
      { name: "scope_id", label: "Parent resource", type: "text", optional: true, placeholder: "projects/my-project/locations/global", help: "Use the same project as AI Studio. Leave blank to use the API key project; set this if your API requires an explicit parent." },
      { name: "api_key", label: "Gemini API key", type: "secret", help: "Reads saved agent inventory. Prompts, sessions and tool credentials are not retained." },
    ],
  },
  claude_agents: {
    ...getConnectorDefinitionBySchemaId("claude_agents"),
    source_kind: "managed_agents",
    permissions: ["Claude API key with Managed Agents read access in the selected workspace. Includes archived agents."],
    fields: [
      { name: "platform", label: "Platform", type: "text", defaultValue: "claude", hidden: true },
      { name: "base_url", label: "API origin", type: "text", defaultValue: "https://api.anthropic.com", hidden: true },
      { name: "scope_id", label: "Workspace ID", type: "text", optional: true, placeholder: "wrkspc_...", help: "Optional with a workspace-scoped key. Include it for credentials that can access multiple workspaces." },
      { name: "api_key", label: "Claude API key", type: "secret", help: "Reads saved agent inventory. Prompts, sessions and tool credentials are not retained." },
    ],
  },
  openai_agents: {
    ...getConnectorDefinitionBySchemaId("openai_agents"),
    source_kind: "managed_agents",
    permissions: ["OpenAI project API key with permission to list agents; Agents API access must be enabled."],
    fields: [
      { name: "platform", label: "Platform", type: "text", defaultValue: "openai", hidden: true },
      { name: "base_url", label: "API origin", type: "text", defaultValue: "https://api.openai.com", hidden: true },
      { name: "scope_id", label: "Project ID", type: "text", optional: true, placeholder: "proj_...", help: "Optional with a project-scoped key. Use the project where the agents were created." },
      { name: "api_key", label: "OpenAI API key", type: "secret", help: "Reads saved agent inventory. Prompts, sessions and tool credentials are not retained." },
    ],
  },
  servicenow_agents: {
    ...getConnectorDefinitionBySchemaId("servicenow_agents"), source_kind: "managed_agents",
    permissions: ["Read ACL on sn_aia_agent through the Table API; OAuth bearer token"],
    fields: [{name:"platform",label:"Platform",type:"text",defaultValue:"servicenow"},{name:"base_url",label:"Instance URL",type:"text",placeholder:"https://company.service-now.com"},{name:"api_key",label:"OAuth access token",type:"secret",help:"Use a read-only integration identity. Refresh expired tokens here."}],
  },
  n8n_agents: {
    ...getConnectorDefinitionBySchemaId("n8n_agents"), source_kind: "managed_agents",
    permissions: ["Public API access with workflow:read; no execution or credential read access needed"],
    fields: [{name:"platform",label:"Platform",type:"text",defaultValue:"n8n"},{name:"base_url",label:"Instance URL",type:"text",placeholder:"https://n8n.company.com"},{name:"api_key",label:"n8n API key",type:"secret"}],
  },
  copilot_studio_agents: {
    ...getConnectorDefinitionBySchemaId("copilot_studio_agents"), source_kind: "managed_agents",
    permissions: ["Dataverse application user with read access to the bot table in this environment; access token for the Dataverse environment audience"],
    fields: [{name:"platform",label:"Platform",type:"text",defaultValue:"copilot_studio"},{name:"base_url",label:"Dataverse environment URL",type:"text",placeholder:"https://company.crm.dynamics.com"},{name:"api_key",label:"OAuth access token",type:"secret",help:"Use a read-only application user. Update expired tokens through this connection."}],
  },
  langgraph_agents: {
    ...getConnectorDefinitionBySchemaId("langgraph_agents"), source_kind: "managed_agents",
    permissions: ["LangSmith API key with access to search assistants on this deployment"],
    fields: [{name:"platform",label:"Platform",type:"text",defaultValue:"langgraph"},{name:"base_url",label:"Deployment URL",type:"text",placeholder:"https://your-deployment.us.langgraph.app"},{name:"api_key",label:"LangSmith API key",type:"secret"}],
  },
  dify_agents: {
    ...getConnectorDefinitionBySchemaId("dify_agents"), source_kind: "managed_agents",
    permissions: ["Application API key for the chosen Dify app; reads basic app metadata only, not workspace-wide inventory, models, tools or executions"],
    fields: [{name:"platform",label:"Platform",type:"text",defaultValue:"dify"},{name:"base_url",label:"API origin",type:"text",placeholder:"https://api.dify.ai"},{name:"app_id",label:"App ID",type:"text",placeholder:"UUID from the app's Studio URL",help:"Each connection inventories this application. Add more connections for other apps."},{name:"api_key",label:"Application API key",type:"secret"}],
  },
  defender_stream: {
    ...getConnectorDefinitionBySchemaId("defender_stream"), source_kind: "browser_upload", uploadAdapter:"defender_stream",
    permissions: ["Defender Streaming API envelope export. For continuous ingestion, deploy the Event Hubs bridge and tallyd collector receive --adapter defender-stream. See https://godel-labs.ai/docs/tally/connectors#uploads-scanner."], fields: [],
  },
  zscaler: {
    ...getConnectorDefinitionBySchemaId("zscaler"),
    source_kind: "browser_upload",
    uploadAdapter: "zscaler",
    permissions: ["An operator-authorized Zscaler NSS JSON or NDJSON export"],
    fields: []
  },
  palo_alto: {
    ...getConnectorDefinitionBySchemaId("palo_alto"),
    source_kind: "browser_upload",
    uploadAdapter: "palo_alto",
    permissions: ["An operator-authorized Palo Alto Strata JSON or NDJSON export"],
    fields: []
  },
  nextdns: {
    ...getConnectorDefinitionBySchemaId("nextdns"),
    source_kind: "nextdns_api",
    permissions: ["profile logs read through X-Api-Key"],
    fields: [
      { name: "profile_id", label: "Profile ID", type: "text", placeholder: "e.g. abc123def456" },
      { name: "api_key", label: "API Key", type: "secret", placeholder: "NextDNS API key" },
      { name: "initial_backfill_seconds", label: "Initial Backfill (seconds)", type: "number", defaultValue: 3600, min: 60, max: 604800, help: "Only the selected bounded window is read when the connector is first added (60 to 604800 seconds)." },
      { name: "initial_record_limit", label: "Records per fetch", type: "number", defaultValue: 1000, help: "Maximum 1000 records; later pages resume from the connector cursor." }
    ]
  },
  ai_gateway: {
    ...getConnectorDefinitionBySchemaId("ai_gateway"),
    source_kind: "ai_gateway_api",
    permissions: ["AI Gateway Read"],
    fields: [
      { name: "account_id", label: "Account ID", type: "text", placeholder: "Cloudflare account ID" },
      { name: "api_token", label: "API Token", type: "secret", placeholder: "Cloudflare API token" },
      { name: "initial_backfill_seconds", label: "Initial Backfill (seconds)", type: "number", defaultValue: 3600, min: 60, max: 604800, help: "Only the selected bounded window is sampled when the connector is first added (60 to 604800 seconds)." },
      { name: "initial_record_limit", label: "Records per poll", type: "number", defaultValue: 1000, help: "Up to 5000 metadata-only AI Gateway logs per import. Tally splits busy time windows and catches up from its cursor." }
    ]
  },
  rapid7_edr: {
    ...getConnectorDefinitionBySchemaId("rapid7_edr"),
    source_kind: "rapid7_edr",
    permissions: ["Insight platform API key with read-only Log Search access to the selected DNS Query log. DNS telemetry must already be collected in InsightIDR; an endpoint agent alone does not supply this log."],
    fields: [
      { name: "region", label: "Rapid7 region", type: "text", defaultValue: "us", help: "Supported regions: us, us2, us3, eu, ca, au, ap." },
      { name: "log_id", label: "DNS Query log ID", type: "text", placeholder: "Log UUID from InsightIDR Log Search", help: "Select a normalized DNS Query log. Raw Endpoint Agent process logs are not supported." },
      { name: "api_key", label: "Insight API key", type: "secret" },
      { name: "initial_backfill_seconds", label: "Initial Backfill (seconds)", type: "number", defaultValue: 3600, min: 60, max: 604800, help: "Reads a bounded window, then resumes from saved pages. Recent events settle for five minutes." },
    ],
  },
  netskope: {
    ...getConnectorDefinitionBySchemaId("netskope"),
    source_kind: "netskope",
    permissions: ["REST API v2 token with Read access to /api/v2/events/data/page or /api/v2/events/data/application, matching the selected event type."],
    fields: [
      { name: "tenant_url", label: "Netskope tenant URL", type: "text", placeholder: "https://company.goskope.com", help: "Use your commercial goskope.com tenant origin, without an API path." },
      { name: "event_type", label: "Event type", type: "text", defaultValue: "page", help: "Use page for web access or application for cloud app activity. Add a separate connection for each type." },
      { name: "api_token", label: "REST API v2 token", type: "secret" },
      { name: "initial_backfill_seconds", label: "Initial Backfill (seconds)", type: "number", defaultValue: 3600, min: 60, max: 604800, help: "Reads a bounded window, then resumes from saved pages. Recent events settle for five minutes." },
    ],
  },
  crowdstrike_edr: {
    ...getConnectorDefinitionBySchemaId("crowdstrike_edr"),
    source_kind: "crowdstrike_edr",
    permissions: [
      "Falcon Insight EDR subscription with endpoint DNS telemetry",
      "Falcon OAuth client with humio-auth-proxy:read access",
      "Operator role with access to search Falcon EDR sensor events in LogScale",
    ],
    fields: [
      {
        name: "cloud",
        label: "Falcon Cloud",
        type: "text",
        defaultValue: "us-1",
        placeholder: "us-1",
        help: "Supported commercial clouds: us-1, us-2, and eu-1. Custom API origins are not accepted.",
      },
      {
        name: "client_id",
        label: "OAuth Client ID",
        type: "secret",
        placeholder: "Falcon API client ID",
      },
      {
        name: "client_secret",
        label: "OAuth Client Secret",
        type: "secret",
        placeholder: "Falcon API client secret",
      },
      {
        name: "initial_backfill_seconds",
        label: "Initial Backfill (seconds)",
        type: "number",
        defaultValue: 3600,
        min: 60,
        max: 604800,
        help: "Reads only the selected bounded DNS-telemetry window on first setup (60 to 604800 seconds).",
      },
      {
        name: "initial_record_limit",
        label: "DNS events per poll",
        type: "number",
        defaultValue: 1000,
        help: "Up to 5000 DNS events per import. Tally splits busy time windows and catches up from its durable cursor; recent events settle for five minutes.",
      },
    ],
  },
  casb_api: {
    ...getConnectorDefinitionBySchemaId("casb_api"),
    source_kind: "casb_api",
    permissions: ["Zero Trust Read"],
    fields: [
      { name: "account_id", label: "Account ID", type: "text", placeholder: "Cloudflare account ID" },
      { name: "api_token", label: "API Token", type: "secret", placeholder: "Cloudflare API token" }
    ]
  },
  zt_gateway: {
    ...getConnectorDefinitionBySchemaId("zt_gateway"),
    source_kind: "cloudflare_zero_trust_gateway",
    permissions: [
      "Account Analytics Read for the default aggregate Gateway HTTP and DNS pull",
      "Optional: a Gateway HTTP (gateway_http) or Network Sessions (zero_trust_network_sessions) Logpush job",
      "Optional: bucket-scoped S3 ListBucket/GetObject credentials for that Logpush destination",
    ],
    fields: [
      { name: "account_id", label: "Cloudflare Account ID", type: "text", placeholder: "32-character Cloudflare account ID", section: "Default Gateway analytics" },
      { name: "api_token", label: "Cloudflare API Token", type: "secret", placeholder: "Cloudflare API token", section: "Default Gateway analytics" },
      { name: "window_seconds", label: "API Window (seconds)", type: "number", defaultValue: 3600, section: "Default Gateway analytics", help: "Reads at most 1000 aggregate HTTP groups and 1000 aggregate DNS groups from closed minute buckets (60 to 604800 seconds). HTTP groups preserve the destination host plus Cloudflare-supplied email, user ID, device ID, and source-internal IP. DNS groups are empty when the account is not using Gateway DNS policies." },
      { name: "endpoint_url", label: "S3-compatible Endpoint", type: "text", placeholder: "https://<ACCOUNT_ID>.r2.cloudflarestorage.com", optional: true, section: "Optional Gateway Logpush", help: "Leave the endpoint, bucket, access key, and secret blank to use the default HTTP and DNS analytics API. If enabled, the bucket must receive gateway_http or zero_trust_network_sessions logs. Network sessions supply sent/received byte counters; HTTP and DNS analytics do not. AI Gateway logs use the separate AI Gateway connector." },
      { name: "bucket", label: "Bucket", type: "text", placeholder: "gateway-http-logs", optional: true, section: "Optional Gateway Logpush" },
      { name: "prefix", label: "Object Prefix", type: "text", placeholder: "tally/gateway-http/", optional: true, section: "Optional Gateway Logpush", help: "Use a dedicated prefix containing only gateway_http and/or zero_trust_network_sessions records so Tally never reads unrelated objects." },
      { name: "region", label: "Signing Region", type: "text", defaultValue: "auto", optional: true, section: "Optional Gateway Logpush", help: "Cloudflare R2 uses auto. Use the configured region for another S3-compatible service." },
      { name: "access_key_id", label: "Access Key ID", type: "secret", placeholder: "S3-compatible access key ID", optional: true, section: "Optional Gateway Logpush" },
      { name: "secret_access_key", label: "Secret Access Key", type: "secret", placeholder: "S3-compatible secret access key", optional: true, section: "Optional Gateway Logpush" },
      { name: "object_limit", label: "Objects per Poll", type: "number", defaultValue: 32, optional: true, section: "Optional Gateway Logpush", help: "Reads 1 to 128 objects in key order and resumes after the last successfully normalized object." },
    ]
  },
  aws_bedrock: {
    ...getConnectorDefinitionBySchemaId("aws_bedrock"),
    source_kind: "managed_cloud",
    adapter: "aws_managed_ai_api",
    permissions: [
      "bedrock:ListProvisionedModelThroughputs",
      "bedrock:ListAgents",
      "bedrock:GetAgent",
      "bedrock:GetInferenceProfile",
      "cloudtrail:LookupEvents",
      "sagemaker:ListEndpoints",
      "sagemaker:ListModels",
    ],
    authentication: {
      credentialFields: ["aws_access_key_id", "aws_secret_access_key"],
      credentialLabel: "Access keys",
      collectorIdentityLabel: "VM service account",
      collectorIdentityHelp: "Uses the IAM role attached to the Tally collector VM.",
    },
    fields: [
      { name: "account_id", label: "AWS Account ID", type: "text", placeholder: "123456789012" },
      { name: "aws_access_key_id", label: "Access Key ID", type: "secret", placeholder: "AKIA..." },
      { name: "aws_secret_access_key", label: "Secret Access Key", type: "secret", placeholder: "AWS secret access key" },
      { name: "region", label: "AWS Region", type: "text", defaultValue: "us-east-1" },
    ]
  },
  aws_vpc_flow_logs: {
    ...getConnectorDefinitionBySchemaId("aws_vpc_flow_logs"),
    source_kind: "cloud_network",
    adapter: "aws_cloud_flow_api",
    permissions: ["ec2:DescribeFlowLogs", "logs:FilterLogEvents"],
    authentication: {
      credentialFields: ["aws_access_key_id", "aws_secret_access_key"],
      credentialLabel: "Access keys",
      collectorIdentityLabel: "VM service account",
      collectorIdentityHelp: "Uses the IAM role attached to the Tally collector VM.",
    },
    fields: [
      { name: "account_id", label: "AWS Account ID", type: "text", placeholder: "123456789012" },
      { name: "network_id", label: "VPC ID", type: "text", placeholder: "vpc-0abc123def4567890" },
      { name: "region", label: "AWS Region", type: "text", defaultValue: "us-east-1" },
      {
        name: "log_group",
        label: "CloudWatch Log Group",
        type: "text",
        placeholder: "/aws/vpc/flowlogs",
        help: "A dedicated, active VPC-level CloudWatch Logs group using the default VPC Flow Logs v2 format",
      },
      { name: "aws_access_key_id", label: "Access Key ID", type: "secret", placeholder: "AKIA..." },
      { name: "aws_secret_access_key", label: "Secret Access Key", type: "secret", placeholder: "AWS secret access key" },
      {
        name: "initial_backfill_seconds",
        label: "Initial Backfill (seconds)",
        type: "number",
        defaultValue: 3600,
        min: 300,
        max: 3600,
        help: "Must be between 300 and 3600 seconds",
      },
    ],
  },
  azure_vnet_flow_logs: {
    ...getConnectorDefinitionBySchemaId("azure_vnet_flow_logs"),
    source_kind: "cloud_network",
    adapter: "azure_cloud_flow_api",
    permissions: [
      "Microsoft.Network/virtualNetworks/read",
      "Microsoft.OperationalInsights/workspaces/read",
      "Microsoft.OperationalInsights/workspaces/query/read",
      "Microsoft.OperationalInsights/workspaces/query/NTANetAnalytics/read",
    ],
    authentication: {
      credentialFields: ["azure_tenant_id", "azure_client_id", "azure_client_secret"],
      credentialLabel: "Service principal",
      collectorIdentityLabel: "Collector identity",
      collectorIdentityHelp: "Uses the collector's Azure credential chain, including workload and managed identity.",
    },
    fields: [
      { name: "account_id", label: "Subscription ID", type: "text", placeholder: "00000000-0000-0000-0000-000000000000" },
      {
        name: "network_id",
        label: "Virtual Network Resource ID",
        type: "text",
        placeholder: "/subscriptions/…/resourceGroups/production/providers/Microsoft.Network/virtualNetworks/main",
      },
      { name: "region", label: "Azure Region", type: "text", defaultValue: "eastus2" },
      {
        name: "workspace_resource",
        label: "Log Analytics Workspace Resource ID",
        type: "text",
        placeholder: "/subscriptions/…/resourceGroups/production/providers/Microsoft.OperationalInsights/workspaces/network-logs",
      },
      { name: "azure_tenant_id", label: "Tenant ID", type: "text", placeholder: "00000000-0000-0000-0000-000000000000" },
      { name: "azure_client_id", label: "Client ID", type: "text", placeholder: "00000000-0000-0000-0000-000000000000" },
      { name: "azure_client_secret", label: "Client Secret", type: "secret", placeholder: "Service principal secret" },
      {
        name: "initial_backfill_seconds",
        label: "Initial Backfill (seconds)",
        type: "number",
        defaultValue: 3600,
        min: 300,
        max: 3600,
        help: "Must be between 300 and 3600 seconds",
      },
    ],
  },
  gcp_vpc_flow_logs: {
    ...getConnectorDefinitionBySchemaId("gcp_vpc_flow_logs"),
    source_kind: "cloud_network",
    adapter: "gcp_cloud_flow_api",
    permissions: ["logging.logEntries.list"],
    authentication: {
      credentialFields: ["gcp_service_account_json"],
      credentialLabel: "Service account key",
      collectorIdentityLabel: "Collector identity",
      collectorIdentityHelp: "Uses application-default credentials, including a VM service account.",
    },
    fields: [
      { name: "account_id", label: "GCP Project ID", type: "text", placeholder: "my-project-id" },
      { name: "network_id", label: "VPC Network Name", type: "text", placeholder: "production-network" },
      {
        name: "gcp_service_account_json",
        label: "Service Account Key JSON",
        type: "secret",
        placeholder: "Paste service account key JSON",
        help: "A service-account key JSON document with permission to list Cloud Logging entries",
      },
      {
        name: "initial_backfill_seconds",
        label: "Initial Backfill (seconds)",
        type: "number",
        defaultValue: 3600,
        min: 300,
        max: 3600,
        help: "Must be between 300 and 3600 seconds",
      },
    ],
  },
  gcp_vertex: {
    ...getConnectorDefinitionBySchemaId("gcp_vertex"),
    source_kind: "managed_cloud",
    adapter: "gcp_vertex_ai_api",
    permissions: [
      "aiplatform.endpoints.list",
      "aiplatform.models.list",
      "logging.logEntries.list for Vertex AI Data Access invocation logs",
      "logging.privateLogEntries.list for restricted Data Access invocation logs",
    ],
    authentication: {
      credentialFields: ["gcp_service_account_json"],
      credentialLabel: "Service account key",
      collectorIdentityLabel: "Collector identity",
      collectorIdentityHelp: "Uses application-default credentials, including a VM service account.",
    },
    fields: [
      { name: "account_id", label: "GCP Project ID", type: "text", placeholder: "my-project-id" },
      { name: "gcp_service_account_json", label: "Service Account Key JSON", type: "secret", placeholder: "Paste service account key JSON", help: "A service-account key JSON document with Vertex AI Viewer, Logs Viewer, and Private Logs Viewer access" },
      { name: "region", label: "GCP Region", type: "text", defaultValue: "us-central1" },
    ]
  },
  azure_openai: {
    ...getConnectorDefinitionBySchemaId("azure_openai"),
    source_kind: "managed_cloud",
    adapter: "azure_openai_api",
    permissions: [
      "Microsoft.CognitiveServices/accounts/read",
      "Microsoft.CognitiveServices/accounts/deployments/read",
      "Microsoft.CognitiveServices/accounts/managedComputeDeployments/read",
      "Microsoft.OperationalInsights/workspaces/read",
      "Microsoft.OperationalInsights/workspaces/query/read",
    ],
    authentication: {
      credentialFields: ["azure_tenant_id", "azure_client_id", "azure_client_secret"],
      credentialLabel: "Service principal",
      collectorIdentityLabel: "Collector identity",
      collectorIdentityHelp: "Uses the collector's Azure credential chain, including workload and managed identity.",
    },
    fields: [
      { name: "account_id", label: "Subscription ID", type: "text", placeholder: "00000000-0000-0000-0000-000000000000" },
      { name: "scope_id", label: "Account Resource ID", type: "text", placeholder: "/subscriptions/…/accounts/my-openai", help: "Cognitive Services account resource ID that scopes the pull" },
      {
        name: "workspace_resource",
        label: "Log Analytics Workspace Resource ID",
        type: "text",
        placeholder: "/subscriptions/…/resourceGroups/production/providers/Microsoft.OperationalInsights/workspaces/openai-logs",
        optional: true,
        help: "Required for Shadow AI request findings. Route AzureOpenAIRequestUsage and RequestResponse diagnostics from this account to the workspace.",
      },
      { name: "azure_tenant_id", label: "Tenant ID", type: "text", placeholder: "00000000-0000-0000-0000-000000000000" },
      { name: "azure_client_id", label: "Client ID", type: "text", placeholder: "00000000-0000-0000-0000-000000000000" },
      { name: "azure_client_secret", label: "Client Secret", type: "secret", placeholder: "Service principal secret" },
      { name: "region", label: "Azure Region", type: "text", defaultValue: "eastus" },
    ]
  },
  litellm: {
    ...getConnectorDefinitionBySchemaId("litellm"),
    source_kind: "litellm_api",
    permissions: [
      "LiteLLM key with read access to GET /model_group/info",
      "LiteLLM key with read access to GET /spend/logs/v2",
    ],
    fields: [
      {
        name: "base_url",
        label: "Base URL",
        type: "text",
        placeholder: "http://localhost:4000",
        help: "HTTPS is required except for an HTTP loopback origin used by the official local Docker quickstart.",
      },
      { name: "api_key", label: "API Key", type: "secret", placeholder: "sk-…" },
      { name: "initial_backfill_seconds", label: "Initial Backfill (seconds)", type: "number", defaultValue: 3600, min: 60, max: 604800, help: "Only request logs from the selected bounded window are read on first setup (60 to 604800 seconds)." },
      { name: "initial_record_limit", label: "Request records per poll", type: "number", defaultValue: 1000, min: 1, max: 5000, help: "Up to 5000 metadata-only spend logs per import across bounded pages. Tally splits busy time windows and catches up from its cursor. LiteLLM must use a database for spend logging." },
    ]
  },
  kubernetes: {
    ...getConnectorDefinitionBySchemaId("kubernetes"),
    source_kind: "kubernetes_api",
    permissions: [
      "get,list namespaces (kube-system included \u2014 the cluster identity derives from it)",
      "get,list services",
      "get,list deployments.apps",
      "get,list statefulsets.apps",
      "get,list daemonsets.apps",
      "get,list jobs.batch",
      "get,list cronjobs.batch",
      "get,list pods",
    ],
    fields: [
      { name: "api_url", label: "API Server URL", type: "text", placeholder: "https://cluster.internal.example:6443", help: "HTTPS API server endpoint. Origin only \u2014 a path, query, or embedded credentials are rejected" },
      { name: "bearer_token", label: "Bearer Token", type: "secret", placeholder: "ServiceAccount token", help: "A long-lived ServiceAccount token. Exec credentials such as aws eks get-token expire between polls" },
      { name: "ca_pem", label: "CA Certificate", type: "file", optional: true, accept: ".pem,.crt,.cer,application/x-pem-file,application/pkix-cert", maxBytes: 1048576, help: "Select the cluster CA certificate from this browser. It is encrypted with the connector credentials; no console filesystem path is required. Leave empty only when the API server chains to a publicly trusted root." },
    ]
  },
  microsoft_defender: {
    ...getConnectorDefinitionBySchemaId("microsoft_defender"),
    source_kind: "microsoft_defender_api",
    permissions: [
      "Microsoft Graph application permission ThreatHunting.Read.All"
    ],
    fields: [
      { name: "tenant_id", label: "Tenant ID", type: "text", placeholder: "Azure AD Tenant ID" },
      { name: "client_id", label: "Client ID", type: "text", placeholder: "App Registration Client ID" },
      { name: "client_secret", label: "Client Secret", type: "secret", placeholder: "App Registration Client Secret" },
      { name: "initial_backfill_seconds", label: "Initial Backfill (seconds)", type: "number", defaultValue: 3600, min: 60, max: 604800, help: "Reads only the selected metadata window on first setup (60 to 604800 seconds)." },
      { name: "initial_record_limit", label: "Network events per poll", type: "number", defaultValue: 1000, help: "Up to 5000 network events per import. Tally splits busy time windows and catches up from its durable cursor; recent events settle for five minutes." }
    ]
  },
  cato_networks: {
    ...getConnectorDefinitionBySchemaId("cato_networks"),
    source_kind: "cato_networks_api",
    permissions: [
      "Cato API read access"
    ],
    fields: [
      { name: "account_id", label: "Account ID", type: "text", placeholder: "Cato Account ID" },
      { name: "api_key", label: "API Key", type: "secret", placeholder: "Cato API Key" },
      { name: "api_hostname", label: "API Hostname", type: "text", defaultValue: "api.catonetworks.com", placeholder: "api.us1.catonetworks.com", help: "Use the hostname for the region that hosts your Cato Management Application." },
      { name: "initial_backfill_seconds", label: "Initial Backfill (seconds)", type: "number", defaultValue: 3600, min: 60, max: 604800, help: "Cato starts a new EventsFeed at the current queue position. This setting is retained for existing schedules; earlier queue history is unavailable without a prior marker." },
      { name: "initial_record_limit", label: "Events per poll", type: "number", defaultValue: 3000, min: 3000, max: 3000, help: "Cato returns up to 3000 events with one marker. Tally imports the full page before advancing that marker." }
    ]
  }
};

interface ConnectorConfigModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  schemaId: ConnectorSchemaId | null;
  existingConnectorId?: string | null;
  /** The name already stored for the connector being edited, so leaving the field alone keeps it. */
  existingFriendlyName?: string | null;
  /** Safe, non-secret values loaded from the connector being edited. */
  existingConfiguration?: Record<string, string> | null;
  credentialReentryRequired?: boolean;
  configuredConnectors?: ConnectorState[];
  jobs?: ConnectorJob[];
  onSelectConnector?: (connector: ConnectorState) => void;
  onNewConnector?: () => void;
  onSyncConnector?: (
    connectorId: string,
  ) => Promise<TallyMutationResult<ConnectorSyncResponse>>;
  onDeleteConnector?: (connectorId: string) => void;
  onSuccess?: () => void;
  /** Optional host UI and permission copy for an embedded deployment. */
  setupContent?: React.ReactNode;
  permissionsOverride?: string[];
  permissionTitle?: string;
  onConfigured?: (connectorId: string) => Promise<void>;
}

type FieldValue = string | number;
type ManagedCloudAuthenticationMode = "credentials" | "collector_identity";

export const FRIENDLY_NAME_MAX_LENGTH = 120;
const MAX_UPLOAD_BYTES = 64 * 1_024 * 1_024;

export function ConnectorConfigModal({
  open,
  onOpenChange,
  schemaId,
  existingConnectorId,
  existingFriendlyName,
  existingConfiguration,
  credentialReentryRequired = false,
  configuredConnectors = [],
  jobs = [],
  onSelectConnector,
  onNewConnector,
  onSyncConnector,
  onDeleteConnector,
  onSuccess,
  setupContent,
  permissionsOverride,
  permissionTitle,
  onConfigured,
}: ConnectorConfigModalProps) {
  const schema = schemaId ? CONNECTOR_SCHEMAS[schemaId] : null;

  const [formData, setFormData] = React.useState<Record<string, FieldValue>>({});
  const [friendlyName, setFriendlyName] = React.useState("");
  const [revealed, setRevealed] = React.useState<Record<string, boolean>>({});
  const [interval, setIntervalVal] = React.useState(300);
  const [paused, setPaused] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [authenticationMode, setAuthenticationMode] =
    React.useState<ManagedCloudAuthenticationMode>("collector_identity");
  const [uploadFile, setUploadFile] = React.useState<File | null>(null);
  const [uploadPreview, setUploadPreview] = React.useState<ImportPreviewResponse | null>(null);
  const [uploadAuthorized, setUploadAuthorized] = React.useState(false);
  const [syncingConnectorId, setSyncingConnectorId] = React.useState<string | null>(null);
  const [connectorActionError, setConnectorActionError] = React.useState<string | null>(null);
  const uploadDataRef = React.useRef<string | null>(null);
  const uploadCheckpointRef = React.useRef<string | null>(null);
  const savedConnectorIdRef = React.useRef<string | null>(null);
  const cloudAuthentication = schema?.authentication;
  const uploadMode = schema?.uploadAdapter !== undefined;
  const existingConfigurationLoading =
    Boolean(existingConnectorId) && !uploadMode && existingConfiguration === undefined;
  const existingConfigurationUnavailable =
    Boolean(existingConnectorId) && !uploadMode && existingConfiguration === null;
  const formDisabled = existingConfigurationLoading || existingConfigurationUnavailable;

  React.useEffect(() => {
    if (open && schema) {
      const initial: Record<string, FieldValue> = {};
      schema.fields.forEach((field) => {
        if (field.defaultValue !== undefined) {
          initial[field.name] = field.defaultValue;
        }
      });
      for (const field of schema.fields) {
        if (field.type === "secret") continue;
        const storedValue = existingConfiguration?.[field.name];
        if (storedValue === undefined) continue;
        const value = field.type === "number" ? Number(storedValue) : storedValue;
        if (!Number.isNaN(value)) {
          initial[field.name] = value;
        }
      }
      // The modal's open transition initializes one coherent form snapshot.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setFormData(initial);
      // New connections start with a useful, editable name. Legacy unnamed connections also get
      // the connector type as a safe default when they are next edited.
      setFriendlyName(existingFriendlyName?.trim() || schema.title);
      // Secrets start masked on every open, including a re-open of the same connector.
      setRevealed({});
      setIntervalVal(300);
      setPaused(false);
      setUploadFile(null);
      setUploadPreview(null);
      setUploadAuthorized(false);
      setConnectorActionError(null);
      uploadDataRef.current = null;
      uploadCheckpointRef.current = null;
      savedConnectorIdRef.current = null;
      setError(
        existingConfigurationUnavailable
          ? "Could not load the existing configuration. It was not changed."
          : null
      );
      const showCredentialFields = cloudAuthentication?.credentialFields.some(
        (fieldName) => existingConfiguration?.[fieldName] !== undefined
      );
      setAuthenticationMode(showCredentialFields || credentialReentryRequired ? "credentials" : "collector_identity");
    }
  }, [open, schema, existingFriendlyName, existingConfiguration, existingConfigurationUnavailable, cloudAuthentication, credentialReentryRequired]);

  if (!schema) return null;

  const visibleFields = schema.fields.filter(
    (field) =>
      !field.hidden && field.name !== "platform" && (!cloudAuthentication ||
      authenticationMode === "credentials" ||
      !cloudAuthentication.credentialFields.includes(field.name)),
  );

  const handleAuthenticationModeChange = (mode: ManagedCloudAuthenticationMode) => {
    setAuthenticationMode(mode);
    if (mode === "collector_identity" && cloudAuthentication) {
      setFormData((previous) => {
        const next = { ...previous };
        cloudAuthentication.credentialFields.forEach((field) => delete next[field]);
        return next;
      });
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (formDisabled) return;

    setError(null);
    const normalizedFriendlyName = friendlyName.trim();
    if (!normalizedFriendlyName) {
      setError("Enter a friendly name for this connection.");
      return;
    }

    if (uploadMode) {
      if (uploadPreview) {
        await commitUpload(normalizedFriendlyName);
      } else {
        await previewUpload();
      }
      return;
    }

    setLoading(true);

    // The API flattens the source into the request body: source_kind and its fields sit
    // alongside the schedule fields, and any unknown key is rejected outright.
    const payload: Record<string, unknown> = {
      source_kind: schema.source_kind,
      interval_seconds: interval,
      paused,
      acknowledge_source_access: true,
      friendly_name: normalizedFriendlyName,
    };

    if (schema.adapter) {
      payload.adapter = schema.adapter;
    }

    schema.fields.forEach((field) => {
      const value = formData[field.name];
      if (value === undefined || value === "") return;
      payload[field.name] = value;
    });

    if (existingConnectorId || savedConnectorIdRef.current) {
      payload.connector_instance_id = existingConnectorId || savedConnectorIdRef.current;
    }

    const result = await scheduleConnector(payload);
    if (result.ok) {
      savedConnectorIdRef.current = result.data.connector_instance_id;
      try {
        await onConfigured?.(result.data.connector_instance_id);
        onSuccess?.();
        onOpenChange(false);
      } catch (cause) {
        const detail = cause instanceof Error ? cause.message : "Additional setup could not be completed.";
        setError(`The connector was saved, but additional setup failed: ${detail}`);
      }
    } else {
      setError(result.error);
    }
    setLoading(false);
  };

  const handleFieldChange = (name: string, value: string, type: string) => {
    const normalized = type === "number" ? Number(value) : value;
    setFormData((previous) => ({ ...previous, [name]: normalized }));
  };

  const handleCredentialFile = async (field: ConnectorSchemaField, file: File | null) => {
    setError(null);
    setFormData((previous) => {
      const next = { ...previous };
      delete next[field.name];
      return next;
    });
    if (!file) {
      return;
    }
    if (file.size === 0 || file.size > (field.maxBytes ?? MAX_UPLOAD_BYTES)) {
      setError(`Choose a non-empty ${field.label} file no larger than ${formatBytes(field.maxBytes ?? MAX_UPLOAD_BYTES)}.`);
      return;
    }
    const value = await file.text();
    setFormData((previous) => ({ ...previous, [field.name]: value }));
  };

  const handleSyncConnector = async (connectorId: string) => {
    if (!onSyncConnector) return;
    setSyncingConnectorId(connectorId);
    setConnectorActionError(null);
    const result = await onSyncConnector(connectorId);
    setSyncingConnectorId(null);
    if (!result.ok) {
      setConnectorActionError(result.error);
    }
  };

  const previewUpload = async () => {
    if (!schema.uploadAdapter || !uploadFile) {
      setError("Choose a JSON or NDJSON export to upload.");
      return;
    }
    if (uploadFile.size === 0 || uploadFile.size > MAX_UPLOAD_BYTES) {
      setError("Choose a non-empty file no larger than 64 MiB.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const data = await uploadFile.text();
      const checkpoint = `browser-upload:${uploadFile.size}:${uploadFile.lastModified}`;
      const response = await tallyFetch("/imports/preview", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          adapter: schema.uploadAdapter,
          connector_instance_id: existingConnectorId || undefined,
          checkpoint,
          data,
        }),
      });
      if (!response.ok) throw new Error(await importProblemMessage(response, "Tally rejected the uploaded file."));
      uploadDataRef.current = data;
      uploadCheckpointRef.current = checkpoint;
      setUploadPreview((await response.json()) as ImportPreviewResponse);
      setUploadAuthorized(false);
    } catch (uploadError) {
      uploadDataRef.current = null;
      uploadCheckpointRef.current = null;
      setUploadPreview(null);
      setError(uploadError instanceof Error ? uploadError.message : "Could not preview the uploaded file.");
    } finally {
      setLoading(false);
    }
  };

  const commitUpload = async (normalizedFriendlyName: string) => {
    if (
      !schema.uploadAdapter ||
      !uploadPreview ||
      !uploadAuthorized ||
      !uploadDataRef.current ||
      !uploadCheckpointRef.current
    ) {
      setError("Review the preview and authorize this exact upload first.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const response = await tallyFetch("/imports", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          adapter: schema.uploadAdapter,
          connector_instance_id: uploadPreview.connector_instance_id,
          checkpoint: uploadCheckpointRef.current,
          data: uploadDataRef.current,
          friendly_name: normalizedFriendlyName,
          confirm_canonical_digest: uploadPreview.canonical_digest,
        }),
      });
      if (!response.ok) throw new Error(await importProblemMessage(response, "Tally did not admit the uploaded batch."));
      void ((await response.json()) as ImportCommitResponse);
      onSuccess?.();
      onOpenChange(false);
    } catch (uploadError) {
      setError(uploadError instanceof Error ? uploadError.message : "Could not import the uploaded file.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[90vh] max-w-5xl flex-col gap-0 overflow-hidden border-border bg-background p-0">
        <form onSubmit={handleSubmit} className="flex flex-col overflow-hidden max-h-full h-full">
          <DialogHeader className="shrink-0 border-b border-border px-5 py-4 pr-12">
            <div className="flex items-center gap-3">
              <VendorBadge vendor={getVendorFromIdentifier(schema.vendorIdentifier)} />
              {existingConnectorId && <Badge variant="secondary" className="text-[10px]">Editing Existing</Badge>}
            </div>
            <DialogTitle className="text-xl">{existingConnectorId ? "Edit" : "Configure"} {schema.title}</DialogTitle>
            <DialogDescription>
              {schema.description}
            </DialogDescription>
          </DialogHeader>
          {setupContent && <div className="shrink-0 border-b border-border px-5 py-3">{setupContent}</div>}

          <div className="custom-scrollbar grid flex-1 gap-5 overflow-y-auto p-5 lg:grid-cols-[minmax(0,1fr)_320px]">
            <div className="min-w-0">

            {/* Help Panel */}
            <div className="mb-6 rounded-lg border border-primary/20 bg-primary/5 p-4 text-sm text-primary">
              <div className="flex items-start gap-2.5">
                <KeyRound className="size-4 shrink-0 mt-0.5" />
                <div className="space-y-1 w-full">
                  <p className="font-semibold">
                    {uploadMode ? "Files are uploaded from this browser" : "Credentials are encrypted at rest"}
                  </p>
                  <p className="opacity-90 leading-relaxed text-xs">
                    {uploadMode
                      ? "No path on the Console host is needed. The selected file stays browser-local until preview, source bytes are normalized in memory, and Tally does not retain the uploaded file. "
                      : existingConnectorId
                      ? "Existing secret values are never fetched or shown. Leave a secret blank to keep it; current non-secret settings are shown below. "
                      : cloudAuthentication && authenticationMode === "collector_identity"
                        ? `${cloudAuthentication.collectorIdentityHelp} `
                      : "Enter the credentials below. "
                    }
                    {!uploadMode ? <>
                      Saving encrypts them with the installation-local{" "}
                      <code className="bg-primary/10 px-1 py-0.5 rounded text-foreground">TALLY_SECRET_KEY</code>{" "}
                      before they reach database. Tally decrypts them only in trusted server memory
                      &mdash; no API ever returns them. The next sync picks up the change within a
                      minute.
                    </> : null}
                  </p>
                  <div className="mt-4 pt-3 border-t border-primary/10 flex items-start gap-2">
                    <ShieldCheck className="size-4 shrink-0 mt-0.5" />
                    <div>
                      <p className="font-semibold">
                        {permissionTitle ?? (uploadMode ? "Required Source Access" : "Required Read-Only Permissions")}
                      </p>
                      <p className="opacity-90 leading-relaxed text-[10px] mt-0.5 mb-1.5">
                        {uploadMode
                          ? "Select an export you are authorized to provide:"
                          : "Ensure the API credentials provided have the following scopes granted:"}
                      </p>
                      <ul className="list-disc list-inside text-[10px] opacity-90 space-y-0.5 ml-1">
                        {(permissionsOverride ?? schema.permissions).map((perm, i) => (
                           <li key={i}>{perm}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {credentialReentryRequired && <div role="alert" className="mb-6 rounded-lg border border-warning/30 bg-warning/10 p-3 text-sm leading-5">
              Tally cannot read this connector&apos;s saved credentials. Enter fresh credentials below and save the connection before retrying the Gate upgrade. The old encrypted values will be replaced only after a valid submission.
            </div>}
            {error && (
              <div className="mb-6 rounded-lg bg-destructive/10 p-3 text-sm text-destructive flex items-center gap-2">
                <AlertCircle className="size-4" />
                {error}
              </div>
            )}

            <div className="space-y-4">
              <div>
                <label
                  htmlFor="connector-friendly-name"
                  className="text-xs font-semibold text-foreground mb-1.5 block"
                >
                  Friendly Name
                  <span className="text-destructive ml-1" aria-hidden="true">*</span>
                </label>
                <Input
                  id="connector-friendly-name"
                  type="text"
                  placeholder={`e.g. Production ${schema.title}`}
                  value={friendlyName}
                  onChange={(event) => setFriendlyName(event.target.value)}
                  maxLength={FRIENDLY_NAME_MAX_LENGTH}
                  required
                  aria-required="true"
                  disabled={formDisabled}
                  spellCheck={false}
                  className="bg-card text-xs"
                />
                <p className="text-[10px] text-muted-foreground mt-1.5">
                  Your own name for this connection, shown across the console and on every piece
                  of evidence it produces. The connector type is supplied as a default; change it
                  to distinguish multiple {schema.title} connections.
                </p>
              </div>

              {uploadMode ? (
                <div className="space-y-3 rounded-lg border border-border bg-card p-4">
                  <label className="text-xs font-semibold text-foreground block">
                    Vendor metadata file
                    <span className="text-destructive ml-1" aria-hidden="true">*</span>
                  </label>
                  <Input
                    type="file"
                    accept=".ndjson,.jsonl,.json,application/x-ndjson,application/json"
                    required={!uploadPreview}
                    disabled={loading}
                    onChange={(event) => {
                      setUploadFile(event.target.files?.[0] ?? null);
                      setUploadPreview(null);
                      setUploadAuthorized(false);
                      uploadDataRef.current = null;
                      uploadCheckpointRef.current = null;
                      setError(null);
                    }}
                    className="bg-card text-xs file:mr-3 file:border-0 file:bg-transparent file:text-xs file:font-semibold"
                  />
                  <p className="text-[10px] text-muted-foreground">
                    JSON or NDJSON, up to 64 MiB. Tally previews the normalized metadata before anything is committed.
                  </p>
                  {uploadFile ? (
                    <p className="text-[10px] font-medium text-foreground">
                      {uploadFile.name} · {uploadFile.size.toLocaleString()} bytes
                    </p>
                  ) : null}
                  {uploadPreview ? (
                    <div className="space-y-3 rounded-lg border border-primary/25 bg-primary/5 p-4">
                      <div className="grid grid-cols-4 gap-2 text-center">
                        <UploadCount label="Read" value={uploadPreview.records_read} />
                        <UploadCount label="Accepted" value={uploadPreview.accepted} />
                        <UploadCount label="Ignored" value={uploadPreview.ignored} />
                        <UploadCount label="Rejected" value={uploadPreview.rejected} />
                      </div>
                      <p className="text-[10px] text-muted-foreground">
                        Source bytes retained: no · content retained: no · preview writes: no
                      </p>
                      <label className="flex items-start gap-2 text-xs text-foreground">
                        <input
                          type="checkbox"
                          checked={uploadAuthorized}
                          onChange={(event) => setUploadAuthorized(event.target.checked)}
                          className="mt-0.5 size-4 accent-primary"
                        />
                        <span>I am authorized to import this source and approve the exact previewed batch.</span>
                      </label>
                    </div>
                  ) : null}
                </div>
              ) : null}

              {cloudAuthentication && (
                <fieldset>
                  <legend className="text-xs font-semibold text-foreground mb-1.5">Authentication</legend>
                  <div className="grid grid-cols-2 gap-2" role="radiogroup" aria-label="Connector authentication mode">
                    <button
                      type="button"
                      role="radio"
                      aria-checked={authenticationMode === "credentials"}
                      onClick={() => handleAuthenticationModeChange("credentials")}
                      disabled={formDisabled}
                      className={cn(
                        "flex min-h-16 items-center gap-2.5 rounded-md border px-3 text-left text-xs transition-colors",
                        authenticationMode === "credentials"
                          ? "border-primary bg-primary/10 text-foreground"
                          : "border-border bg-card text-muted-foreground hover:bg-muted/50 hover:text-foreground",
                      )}
                    >
                      <KeyRound className="size-4 shrink-0" />
                      <span className="font-medium">{cloudAuthentication.credentialLabel}</span>
                    </button>
                    <button
                      type="button"
                      role="radio"
                      aria-checked={authenticationMode === "collector_identity"}
                      onClick={() => handleAuthenticationModeChange("collector_identity")}
                      disabled={formDisabled}
                      className={cn(
                        "flex min-h-16 items-center gap-2.5 rounded-md border px-3 text-left text-xs transition-colors",
                        authenticationMode === "collector_identity"
                          ? "border-primary bg-primary/10 text-foreground"
                          : "border-border bg-card text-muted-foreground hover:bg-muted/50 hover:text-foreground",
                      )}
                    >
                      <Server className="size-4 shrink-0" />
                      <span className="font-medium">{cloudAuthentication.collectorIdentityLabel}</span>
                    </button>
                  </div>
                  <p className="text-[10px] text-muted-foreground mt-1.5">
                    {cloudAuthentication.collectorIdentityHelp}
                  </p>
                </fieldset>
              )}

              <div className="grid grid-cols-2 gap-4">
                {visibleFields.map((field, index) => {
                  const isSecret = field.type === "secret";
                  const isCredentialFile = field.type === "file";
                  const isVisible = revealed[field.name] === true;
                  const showSection =
                    field.section && field.section !== visibleFields[index - 1]?.section;
                  return (
                    <React.Fragment key={field.name}>
                    {showSection ? (
                      <div className="col-span-2 border-b border-border pb-2 pt-2">
                        <p className="text-xs font-semibold text-foreground">{field.section}</p>
                      </div>
                    ) : null}
                    <div className={isSecret || isCredentialFile ? "col-span-2" : "col-span-1"}>
                      <label
                        htmlFor={`connector-field-${field.name}`}
                        className="text-xs font-semibold text-foreground mb-1.5 block"
                      >
                        {field.label}
                        {(isSecret || isCredentialFile) && (
                          <span className="text-muted-foreground font-normal ml-1">(encrypted)</span>
                        )}
                        {field.optional && (
                          <span className="text-muted-foreground font-normal ml-1">(optional)</span>
                        )}
                      </label>
                      <div className="relative">
                        {isCredentialFile ? (
                          <Input
                            id={`connector-field-${field.name}`}
                            type="file"
                            accept={field.accept}
                            required={!field.optional && !existingConnectorId}
                            disabled={formDisabled}
                            onChange={(event) => void handleCredentialFile(field, event.target.files?.[0] ?? null)}
                            className="bg-card text-xs file:mr-3 file:border-0 file:bg-transparent file:text-xs file:font-semibold"
                          />
                        ) : (
                          <Input
                            id={`connector-field-${field.name}`}
                            type={isSecret && !isVisible ? "password" : field.type === "number" ? "number" : "text"}
                            placeholder={existingConnectorId ? "<--REDACTED-->" : field.placeholder}
                            value={formData[field.name] ?? ""}
                            min={field.min}
                            max={field.max}
                            onChange={(event) =>
                              handleFieldChange(field.name, event.target.value, field.type)
                            }
                            required={!field.optional && (!isSecret || !existingConnectorId)}
                            disabled={formDisabled}
                            autoComplete={isSecret ? "new-password" : "off"}
                            spellCheck={false}
                            className={cn("bg-card font-mono text-xs", isSecret && "pr-10")}
                          />
                        )}
                        {isSecret && (
                          <button
                            type="button"
                            onClick={() =>
                              setRevealed((previous) => ({
                                ...previous,
                                [field.name]: !previous[field.name],
                              }))
                            }
                            disabled={formDisabled}
                            aria-label={isVisible ? `Hide ${field.label}` : `Show ${field.label}`}
                            className="absolute inset-y-0 right-0 flex items-center px-3 text-muted-foreground hover:text-foreground"
                          >
                            {isVisible ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
                          </button>
                        )}
                      </div>
                      {field.help && <p className="text-[10px] text-muted-foreground mt-1.5">{field.help}</p>}
                    </div>
                    </React.Fragment>
                  );
                })}
              </div>

              {!uploadMode ? <div className="grid grid-cols-2 gap-4 pt-2 border-t border-border mt-4">
                 <div>
                    <label className="text-xs font-semibold text-foreground mb-1.5 block">
                      Sync Interval (seconds)
                    </label>
                    <Input
                      type="number"
                      value={interval}
                      onChange={(e) => setIntervalVal(Number(e.target.value))}
                      min={60}
                      max={86400}
                      required
                      disabled={formDisabled}
                      className="bg-card"
                    />
                 </div>
                 <div className="flex flex-col justify-center pt-5">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input 
                        type="checkbox" 
                        checked={paused}
                        onChange={(e) => setPaused(e.target.checked)}
                        disabled={formDisabled}
                        className="rounded border-border text-primary focus:ring-primary size-4"
                      />
                      <span className="text-sm font-medium text-foreground">Pause Connector</span>
                    </label>
                 </div>
              </div> : null}
            </div>
            </div>
            <ConfiguredConnectorSidebar
              connectors={configuredConnectors}
              jobs={jobs}
              selectedConnectorId={existingConnectorId}
              syncingConnectorId={syncingConnectorId}
              actionError={connectorActionError}
              canSync={Boolean(onSyncConnector)}
              canDelete={Boolean(onDeleteConnector)}
              onSelect={onSelectConnector}
              onNew={onNewConnector}
              onSync={handleSyncConnector}
              onDelete={onDeleteConnector}
            />
          </div>

          <div className="p-4 bg-muted/40 border-t border-border mt-auto shrink-0 space-y-4">
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={loading || formDisabled || (uploadMode && Boolean(uploadPreview) && !uploadAuthorized)}
              >
                {existingConfigurationLoading
                  ? "Loading..."
                  : loading
                    ? "Saving..."
                    : uploadMode
                      ? uploadPreview
                        ? uploadAuthorized
                          ? "Import Previewed File"
                          : "Authorize Import"
                        : "Preview Upload"
                    : existingConnectorId
                      ? "Update Connector"
                      : "Add Connector"}
              </Button>
            </DialogFooter>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function ConfiguredConnectorSidebar({
  connectors,
  jobs,
  selectedConnectorId,
  syncingConnectorId,
  actionError,
  canSync,
  canDelete,
  onSelect,
  onNew,
  onSync,
  onDelete,
}: {
  connectors: ConnectorState[];
  jobs: ConnectorJob[];
  selectedConnectorId?: string | null;
  syncingConnectorId: string | null;
  actionError: string | null;
  canSync: boolean;
  canDelete: boolean;
  onSelect?: (connector: ConnectorState) => void;
  onNew?: () => void;
  onSync: (connectorId: string) => Promise<void>;
  onDelete?: (connectorId: string) => void;
}) {
  return (
    <aside className="space-y-3 border-t border-border pt-5 lg:sticky lg:top-0 lg:self-start lg:border-t-0 lg:pt-0">
      <div className="flex items-center justify-between gap-2">
        <div>
          <h3 className="text-sm font-semibold text-foreground">Configured</h3>
          <p className="mt-0.5 text-[10px] text-muted-foreground">
            Select a connection to edit it.
          </p>
        </div>
        <Button
          type="button"
          size="sm"
          className="gap-1.5"
          disabled={!onNew}
          onClick={onNew}
        >
          <Plus className="size-3.5" />
          New
        </Button>
      </div>

      {actionError ? (
        <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
          {actionError}
        </div>
      ) : null}

      {connectors.length === 0 ? (
        <p className="rounded-md border border-dashed border-border px-3 py-4 text-center text-xs text-muted-foreground">
          No connections configured yet.
        </p>
      ) : (
        <div className="space-y-2">
          {connectors.map((connector) => {
            const job = jobs.find(
              (candidate) => candidate.connector_instance_id === connector.connector_instance_id,
            );
            const running = job?.leased === true;
            const syncBlockedReason = !job
              ? "No schedule is registered for this connection."
              : running
                ? "A sync is already running."
                : job.status !== "enabled"
                  ? "This connection is paused."
                  : null;
            const selected = selectedConnectorId === connector.connector_instance_id;
            const syncing = syncingConnectorId === connector.connector_instance_id;
            const name = connector.friendly_name?.trim() || connector.display_name;
            return (
              <div
                key={connector.connector_instance_id}
                role="button"
                tabIndex={0}
                aria-current={selected ? "true" : undefined}
                onClick={() => onSelect?.(connector)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onSelect?.(connector);
                  }
                }}
                className={cn(
                  "cursor-pointer rounded-md border p-3 text-left transition-colors",
                  selected
                    ? "border-primary bg-primary/5"
                    : "border-border hover:bg-muted/50",
                )}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="truncate text-sm font-medium text-foreground">{name}</div>
                    <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-[10px] text-muted-foreground">
                      <Badge
                        variant={
                          connector.health === "healthy"
                            ? "success"
                            : connector.health === "error"
                              ? "destructive"
                              : "secondary"
                        }
                        className="capitalize text-[9px]"
                      >
                        {connector.health.replaceAll("_", " ")}
                      </Badge>
                      <span>{connector.records_read_total.toLocaleString()} records</span>
                    </div>
                    <p className="mt-1.5 text-[10px] text-muted-foreground">
                      {connector.last_success_at
                        ? `Last synced ${formatTimeAgo(connector.last_success_at)}`
                        : "Never synced"}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-0.5">
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="size-7 text-muted-foreground hover:text-primary"
                      disabled={syncing || !canSync || syncBlockedReason !== null}
                      title={syncBlockedReason ?? "Sync now"}
                      aria-label={`Sync ${name}`}
                      onClick={(event) => {
                        event.stopPropagation();
                        void onSync(connector.connector_instance_id);
                      }}
                    >
                      <RefreshCw
                        className={cn("size-3.5", (syncing || running) && "animate-spin")}
                      />
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="size-7 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
                      disabled={!canDelete}
                      title="Delete connection"
                      aria-label={`Delete ${name}`}
                      onClick={(event) => {
                        event.stopPropagation();
                        onDelete?.(connector.connector_instance_id);
                      }}
                    >
                      <Trash2 className="size-3.5" />
                    </Button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </aside>
  );
}

function UploadCount({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-border bg-background p-2">
      <p className="text-[9px] uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="mt-1 text-sm font-bold">{value.toLocaleString()}</p>
    </div>
  );
}

function formatBytes(value: number) {
  if (value >= 1_024 * 1_024) return `${Math.floor(value / (1_024 * 1_024))} MiB`;
  if (value >= 1_024) return `${Math.floor(value / 1_024)} KiB`;
  return `${value} bytes`;
}

function formatTimeAgo(iso: string) {
  const timestamp = new Date(iso).getTime();
  if (Number.isNaN(timestamp)) return "recently";
  const minutes = Math.max(0, Math.floor((Date.now() - timestamp) / 60_000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

async function importProblemMessage(response: Response, fallback: string) {
  try {
    const body = (await response.json()) as { title?: string };
    return body.title ?? fallback;
  } catch {
    return fallback;
  }
}
