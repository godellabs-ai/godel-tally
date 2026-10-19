//! Real product names, with fictional enterprise activity and private record identities.
pub(super) struct Provider {
    // Canonical identity is for default-decision parity only; persisted sample keys stay private.
    pub registry_key: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    pub country: &'static str,
    pub gateway: &'static str,
    pub models: [usize; 3],
}

impl Provider {
    /// Evaluation defaults mirror `tally_default_provider_sanction`; the live test checks parity.
    pub fn sanctioned(&self) -> bool {
        matches!(
            self.registry_key,
            "openai"
                | "anthropic"
                | "google"
                | "google-vertex-ai"
                | "azure-ai"
                | "microsoft"
                | "microsoft-365-copilot"
                | "github"
                | "aws-bedrock"
                | "cohere"
                | "mistral"
                | "databricks"
                | "snowflake"
                | "ibm-watsonx"
        )
    }
}

pub(super) struct Model {
    pub name: &'static str,
    pub family: &'static str,
    pub owner: usize,
    pub modalities: &'static [&'static str],
    pub capabilities: &'static [&'static str],
}

pub(super) const PROVIDERS: [Provider; 14] = [
    Provider {
        registry_key: "openai",
        name: "OpenAI",
        category: "direct_provider",
        country: "US",
        gateway: "openai",
        models: [0, 1, 2],
    },
    Provider {
        registry_key: "anthropic",
        name: "Anthropic",
        category: "direct_provider",
        country: "US",
        gateway: "anthropic",
        models: [3, 4, 3],
    },
    Provider {
        registry_key: "google",
        name: "Google AI",
        category: "direct_provider",
        country: "US",
        gateway: "gemini",
        models: [5, 6, 5],
    },
    Provider {
        registry_key: "aws-bedrock",
        name: "Amazon Bedrock",
        category: "managed_platform",
        country: "US",
        gateway: "bedrock",
        models: [3, 4, 7],
    },
    Provider {
        registry_key: "azure-ai",
        name: "Azure AI Foundry",
        category: "managed_platform",
        country: "US",
        gateway: "azure-ai",
        models: [0, 1, 9],
    },
    Provider {
        registry_key: "google-vertex-ai",
        name: "Google Vertex AI",
        category: "managed_platform",
        country: "US",
        gateway: "vertex-ai",
        models: [5, 6, 5],
    },
    Provider {
        registry_key: "litellm",
        name: "LiteLLM",
        category: "ai_gateway",
        country: "US",
        gateway: "litellm",
        models: [0, 3, 2],
    },
    Provider {
        registry_key: "cloudflare",
        name: "Cloudflare AI Gateway",
        category: "ai_gateway",
        country: "US",
        gateway: "cloudflare-ai",
        models: [0, 3, 6],
    },
    Provider {
        registry_key: "ollama",
        name: "Ollama",
        category: "local_runtime",
        country: "US",
        gateway: "ollama",
        models: [7, 8, 7],
    },
    Provider {
        registry_key: "vllm",
        name: "vLLM",
        category: "inference_server",
        country: "US",
        gateway: "vllm",
        models: [7, 8, 7],
    },
    Provider {
        registry_key: "microsoft-365-copilot",
        name: "Microsoft 365 Copilot",
        category: "enterprise_application",
        country: "US",
        gateway: "copilot",
        models: [0, 1, 0],
    },
    Provider {
        registry_key: "servicenow",
        name: "ServiceNow Now Assist",
        category: "enterprise_application",
        country: "US",
        gateway: "servicenow",
        models: [0, 1, 0],
    },
    Provider {
        registry_key: "meta",
        name: "Meta",
        category: "direct_provider",
        country: "US",
        gateway: "llama",
        models: [7, 7, 7],
    },
    Provider {
        registry_key: "alibaba-qwen",
        name: "Alibaba Cloud Qwen",
        category: "managed_platform",
        country: "CN",
        gateway: "qwen",
        models: [8, 8, 8],
    },
];

// Names and capabilities follow Tally's shipped catalog. Aliases are deliberately NOT copied:
// evaluation records must never capture live imports resolving canonical model identifiers.
pub(super) const MODELS: [Model; 10] = [
    Model {
        name: "GPT-4o",
        family: "GPT-4",
        owner: 0,
        modalities: &["text", "image"],
        capabilities: &["chat", "vision", "tool_use"],
    },
    Model {
        name: "GPT-4o mini",
        family: "GPT-4",
        owner: 0,
        modalities: &["text", "image"],
        capabilities: &["chat", "vision", "tool_use"],
    },
    Model {
        name: "Whisper",
        family: "Whisper",
        owner: 0,
        modalities: &["audio", "text"],
        capabilities: &["speech_recognition"],
    },
    Model {
        name: "Claude Sonnet 4",
        family: "Claude 4",
        owner: 1,
        modalities: &["text", "image"],
        capabilities: &["chat", "reasoning", "coding", "tool_use"],
    },
    Model {
        name: "Claude 3.5 Haiku",
        family: "Claude 3",
        owner: 1,
        modalities: &["text", "image"],
        capabilities: &["chat", "tool_use"],
    },
    Model {
        name: "Gemini 2.5 Pro",
        family: "Gemini 2.5",
        owner: 2,
        modalities: &["text", "image", "audio", "video"],
        capabilities: &["chat", "reasoning", "coding", "tool_use"],
    },
    Model {
        name: "Gemini 2.5 Flash",
        family: "Gemini 2.5",
        owner: 2,
        modalities: &["text", "image", "audio", "video"],
        capabilities: &["chat", "reasoning", "tool_use"],
    },
    Model {
        name: "Llama 3.3",
        family: "Llama 3",
        owner: 12,
        modalities: &["text"],
        capabilities: &["chat", "reasoning"],
    },
    Model {
        name: "Qwen2.5-VL",
        family: "Qwen",
        owner: 13,
        modalities: &["text", "image", "video"],
        capabilities: &["chat", "vision", "tool_use"],
    },
    Model {
        name: "GPT Image 1",
        family: "GPT Image",
        owner: 0,
        modalities: &["text", "image"],
        capabilities: &["image_generation", "image_editing"],
    },
];

/// Cloud and gateway inventory must agree with its source; broad discovery sources see a mix.
pub(super) fn provider_for(connector: &str, index: usize, scenario: usize) -> usize {
    if connector == "openai_agents_api_v1" {
        0
    } else if connector == "claude_agents_api_v1" {
        1
    } else if connector == "gemini_agents_api_v1" {
        2
    } else if connector.starts_with("aws") {
        3
    } else if connector.starts_with("azure") || connector.contains("copilot_studio") {
        4
    } else if connector.starts_with("gcp") {
        5
    } else if connector.starts_with("litellm") {
        6
    } else if connector.starts_with("cloudflare_ai_gateway") {
        7
    } else if connector.contains("servicenow") {
        11
    } else if connector.contains("casb") {
        [10, 11, 2][scenario]
    } else if connector.contains("scanner") || connector.contains("kubernetes") {
        [8, 9, 6][scenario]
    } else {
        [0, 1, 2, 6, 8, 9, 10][(index + scenario) % 7]
    }
}

pub(super) fn platform_for(connector: &str) -> &'static str {
    if connector.contains("n8n") {
        "n8n"
    } else if connector.contains("servicenow") {
        "ServiceNow"
    } else if connector.contains("copilot_studio") {
        "Copilot Studio"
    } else if connector.contains("dify") {
        "Dify"
    } else {
        "LangGraph"
    }
}

pub(super) const PEOPLE: [(&str, &str, &str); 6] = [
    ("maya.chen", "MBP-MCHEN-014", "Research"),
    ("alex.rivera", "MBP-ARIVERA-028", "Customer Support"),
    ("sam.patel", "DEV-SPATEL-006", "Engineering"),
    ("priya.shah", "MBP-PSHAH-031", "Finance"),
    ("james.wilson", "DEV-JWILSON-019", "Platform"),
    ("sofia.martinez", "MBP-SMARTINEZ-042", "Operations"),
];

pub(super) const AGENTS: [(&str, &str); 6] = [
    ("Market Research Analyst", "market-research"),
    ("Customer Support Copilot", "support-copilot"),
    ("Pull Request Reviewer", "code-review"),
    ("Invoice Reconciliation", "invoice-reconciliation"),
    ("Incident Triage", "incident-triage"),
    ("Knowledge Search", "knowledge-search"),
];
