import * as React from "react";
import Image, { type StaticImageData } from "next/image";
import {
  Cpu,
  Globe,
  Network,
  Server,
  Shield,
  Sparkles,
} from "lucide-react";
import { cn } from "@/lib/utils";

// Static imports bundle the same brand assets in standalone Tally and embedded hosts.
import cloudflareLogo from "../public/icons/cloudflare.png";
import awsLogo from "../public/icons/aws-bedrock.png";
import azureLogo from "../public/icons/azure-foundry.png";
import gcpLogo from "../public/icons/google-vertex.png";
import kubernetesLogo from "../public/icons/kubernetes.png";
import palo_altoLogo from "../public/icons/palo-alto.png";
import zscalerLogo from "../public/icons/zscalar.png";
import litellmLogo from "../public/icons/litellm.png";
import nextdnsLogo from "../public/icons/nextdns.png";
import tallyLogo from "../public/icons/tally.png";
import rapid7Logo from "../public/logos/rapid7.png";
import netskopeLogo from "../public/logos/netskope.png";
import crowdstrikeLogo from "../public/logos/crowdstrike.png";
import cato_networksLogo from "../public/logos/cato-networks.png";
import servicenowLogo from "../public/logos/servicenow.png";
import n8nLogo from "../public/logos/n8n.png";
import microsoftLogo from "../public/logos/microsoft.png";
import copilotLogo from "../public/logos/copilot.png";
import langgraphLogo from "../public/logos/langgraph.png";
import difyLogo from "../public/logos/dify.png";
import openaiLogo from "../public/logos/openai.png";
import anthropicLogo from "../public/logos/anthropic.png";
import metaLogo from "../public/logos/meta.png";
import ollamaLogo from "../public/logos/ollama.png";

export type VendorType =
  | "cloudflare"
  | "aws"
  | "azure"
  | "gcp"
  | "openai"
  | "anthropic"
  | "meta"
  | "kubernetes"
  | "nextdns"
  | "zscaler"
  | "palo_alto"
  | "litellm"
  | "rapid7"
  | "netskope"
  | "crowdstrike"
  | "ollama"
  | "tally"
  | "cato_networks"
  | "microsoft"
  | "copilot"
  | "servicenow"
  | "n8n"
  | "langgraph"
  | "dify"
  | "other";

export const vendorImageMap: Partial<Record<VendorType, StaticImageData>> = {
  cloudflare: cloudflareLogo,
  aws: awsLogo,
  azure: azureLogo,
  gcp: gcpLogo,
  kubernetes: kubernetesLogo,
  palo_alto: palo_altoLogo,
  zscaler: zscalerLogo,
  litellm: litellmLogo,
  nextdns: nextdnsLogo,
  tally: tallyLogo,
  rapid7: rapid7Logo,
  netskope: netskopeLogo,
  crowdstrike: crowdstrikeLogo,
  cato_networks: cato_networksLogo,
  servicenow: servicenowLogo,
  n8n: n8nLogo,
  microsoft: microsoftLogo,
  copilot: copilotLogo,
  langgraph: langgraphLogo,
  dify: difyLogo,
  openai: openaiLogo,
  anthropic: anthropicLogo,
  meta: metaLogo,
  ollama: ollamaLogo,
};

export function getVendorFromIdentifier(id: string): VendorType {
  const lower = (id || "").toLowerCase();
  if (lower.includes("rapid7")) return "rapid7";
  if (lower.includes("netskope")) return "netskope";
  if (lower.includes("servicenow")) return "servicenow";
  if (lower.includes("n8n")) return "n8n";
  if (lower.includes("langgraph") || lower.includes("langsmith")) return "langgraph";
  if (lower.includes("dify")) return "dify";
  if (lower.includes("copilot")) return "copilot";
  if (lower.includes("defender") || lower === "microsoft") return "microsoft";
  if (lower.includes("ollama")) return "ollama";
  if (
    lower.includes("cloudflare") ||
    lower.includes("workers-ai") ||
    lower.includes("cf/") ||
    lower.includes("ai_gateway") ||
    lower.includes("zt_gateway") ||
    lower.includes("casb")
  )
    return "cloudflare";
  if (
    lower.includes("aws") ||
    lower.includes("bedrock") ||
    lower.includes("sagemaker") ||
    (lower.includes("cloud_flow") && lower.includes("aws"))
  )
    return "aws";
  if (
    lower.includes("azure") ||
    lower.includes("foundry") ||
    lower.includes("microsoft") ||
    (lower.includes("cloud_flow") && lower.includes("azure"))
  )
    return "azure";
  if (
    lower.includes("gcp") ||
    lower.includes("vertex") ||
    lower.includes("google") ||
    lower.includes("gemma") ||
    (lower.includes("cloud_flow") && lower.includes("gcp"))
  )
    return "gcp";
  if (lower.includes("openai") || lower.includes("gpt")) return "openai";
  if (lower.includes("anthropic") || lower.includes("claude")) return "anthropic";
  if (lower.includes("meta") || lower.includes("llama")) return "meta";
  if (
    lower.includes("kubernetes") ||
    lower.includes("k8s") ||
    lower.includes("k3s") ||
    lower.includes("kube")
  )
    return "kubernetes";
  if (lower.includes("nextdns")) return "nextdns";
  if (lower.includes("zscaler") || lower.includes("zscalar")) return "zscaler";
  if (
    lower.includes("palo_alto") ||
    lower.includes("palo-alto") ||
    lower.includes("paloalto") ||
    lower.includes("strata") ||
    lower.includes("pan_")
  )
    return "palo_alto";
  if (lower.includes("litellm")) return "litellm";
  if (lower.includes("crowdstrike") || lower.includes("falcon") || lower.includes("edr")) return "crowdstrike";
  if (lower.includes("ollama")) return "ollama";
  if (lower.includes("tally")) return "tally";
  if (lower.includes("cato_networks") || lower.includes("cato-networks") || lower.includes("cato")) return "cato_networks";
  return "other";
}

export function VendorBadge({
  vendor,
  name,
  className,
}: {
  vendor: VendorType;
  name?: string;
  className?: string;
}) {
  const meta = vendorMetadata[vendor] || vendorMetadata.other;
  return (
    <div className={cn("inline-flex items-center gap-1.5", className)}>
      <VendorIcon vendor={vendor} className="size-4 shrink-0" />
      <span className="text-xs font-semibold">{name !== undefined ? name : meta.label}</span>
    </div>
  );
}

export function VendorIcon({
  vendor,
  className,
}: {
  vendor: VendorType;
  className?: string;
}) {
  const imageSrc = vendorImageMap[vendor];

  if (imageSrc) {
    return (
      <Image
        src={imageSrc}
        alt={vendorMetadata[vendor].label}
        width={16}
        height={16}
        className={cn("size-4 object-contain shrink-0 rounded-xs dark:bg-white/95 dark:p-0.5", className, vendor === "servicenow" && "w-10")}
        loading="lazy"
        unoptimized
      />
    );
  }

  switch (vendor) {
    case "openai":
      return (
        <div
          className={cn(
            "grid size-4 place-items-center rounded bg-[#10A37F]/15 text-[#10A37F]",
            className
          )}
        >
          <Cpu className="size-3" strokeWidth={2.5} />
        </div>
      );
    case "anthropic":
      return (
        <div
          className={cn(
            "grid size-4 place-items-center rounded bg-[#D97706]/15 text-[#D97706]",
            className
          )}
        >
          <Sparkles className="size-3" strokeWidth={2.5} />
        </div>
      );
    case "meta":
      return (
        <div
          className={cn(
            "grid size-4 place-items-center rounded bg-[#0668E1]/15 text-[#0668E1]",
            className
          )}
        >
          <Cpu className="size-3" strokeWidth={2.5} />
        </div>
      );
    case "nextdns":
      return (
        <div
          className={cn(
            "grid size-4 place-items-center rounded bg-emerald-500/15 text-emerald-600",
            className
          )}
        >
          <Globe className="size-3" strokeWidth={2.5} />
        </div>
      );
    case "litellm":
      return (
        <div
          className={cn(
            "grid size-4 place-items-center rounded bg-[#8B5CF6]/15 text-[#8B5CF6]",
            className
          )}
        >
          <Network className="size-3" strokeWidth={2.5} />
        </div>
      );
    case "rapid7":
    case "netskope":
    case "crowdstrike":
      return (
        <div
          className={cn(
            "grid size-4 place-items-center rounded bg-red-500/15 text-red-600 dark:text-red-400",
            className
          )}
        >
          <Shield className="size-3" strokeWidth={2.5} />
        </div>
      );
    case "ollama":
      return (
        <div
          className={cn(
            "grid size-4 place-items-center rounded bg-slate-500/15 text-slate-600 dark:text-slate-300",
            className
          )}
        >
          <Server className="size-3" strokeWidth={2.5} />
        </div>
      );
    case "tally":
      return (
        <div
          className={cn(
            "grid size-4 place-items-center rounded bg-primary/15 text-primary",
            className
          )}
        >
          <Sparkles className="size-3" strokeWidth={2.5} />
        </div>
      );
    default:
      return (
        <div
          className={cn(
            "grid size-4 place-items-center rounded bg-muted text-muted-foreground",
            className
          )}
        >
          <Cpu className="size-3" strokeWidth={2.5} />
        </div>
      );
  }
}

export const vendorMetadata: Record<
  VendorType,
  { label: string; tone: string; description: string }
> = {
  cloudflare: {
    label: "Cloudflare",
    tone: "#F38020",
    description: "AI Gateway, Workers AI, Zero Trust & CASB",
  },
  aws: {
    label: "Amazon Web Services",
    tone: "#FF9900",
    description: "Amazon Bedrock & SageMaker deployments",
  },
  azure: {
    label: "Microsoft Azure",
    tone: "#0078D4",
    description: "Azure OpenAI & Microsoft Foundry models",
  },
  gcp: {
    label: "Google Cloud",
    tone: "#4285F4",
    description: "Google Vertex AI & Gemini model garden",
  },
  openai: {
    label: "OpenAI",
    tone: "#10A37F",
    description: "Direct API endpoints and enterprise accounts",
  },
  anthropic: {
    label: "Anthropic",
    tone: "#D97706",
    description: "Claude API and developer models",
  },
  meta: {
    label: "Meta AI",
    tone: "#0668E1",
    description: "Llama open model family & runtimes",
  },
  kubernetes: {
    label: "Kubernetes",
    tone: "#326CE5",
    description: "Cluster workloads, pods & self-hosted LLMs",
  },
  nextdns: {
    label: "NextDNS",
    tone: "#10B981",
    description: "DNS resolution & domain queries",
  },
  zscaler: {
    label: "Zscaler",
    tone: "#2563EB",
    description: "Zero Trust Exchange Secure Web Gateway",
  },
  palo_alto: {
    label: "Palo Alto Networks",
    tone: "#DC2626",
    description: "Strata Next-Gen Firewall & DNS Security",
  },
  litellm: {
    label: "LiteLLM Proxy",
    tone: "#8B5CF6",
    description: "Self-hosted AI gateway & proxy router",
  },
  rapid7: { label: "Rapid7", tone: "#E85E26", description: "InsightIDR DNS telemetry" },
  netskope: { label: "Netskope", tone: "#00A6A6", description: "Secure web and cloud application activity" },
  crowdstrike: {
    label: "CrowdStrike",
    tone: "#E01F26",
    description: "Falcon EDR endpoint DNS telemetry",
  },
  ollama: {
    label: "Ollama",
    tone: "#64748B",
    description: "Local endpoint runtimes & workstation models",
  },
  tally: {
    label: "Gödel Tally",
    tone: "#674AF4",
    description: "Tally native capability scanner",
  },
  cato_networks: {
    label: "Cato Networks",
    tone: "#0072C6",
    description: "Cato SASE Cloud Secure Access",
  },
  microsoft: { label: "Microsoft", tone: "#0078D4", description: "Microsoft Defender endpoint telemetry" },
  copilot: { label: "Microsoft Copilot Studio", tone: "#674AF4", description: "Managed Copilot agents" },
  servicenow: { label: "ServiceNow", tone: "#62D84E", description: "AI Agent Studio inventory" },
  n8n: { label: "n8n", tone: "#EA4B71", description: "AI workflows and agent nodes" },
  langgraph: { label: "LangSmith / LangGraph", tone: "#1C3C3C", description: "Assistants and agent graphs" },
  dify: { label: "Dify", tone: "#1C64F2", description: "AI agent and workflow applications" },
  other: {
    label: "Generic AI",
    tone: "#6B7280",
    description: "Unclassified AI service or model endpoint",
  },
};
