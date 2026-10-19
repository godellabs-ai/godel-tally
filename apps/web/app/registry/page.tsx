"use client";
import { RegistryWorkspace } from "@/components/registry-workspace";
import { PageData } from "@/components/page-data";
import { getProviderDomains, getRegistryModels, getRegistryProviders } from "@/lib/tally";
async function load() {
  const [providers, models, domains] = await Promise.all([getRegistryProviders(), getRegistryModels(), getProviderDomains()]);
  return providers && models && domains ? { providers, models, domains } : null;
}
export default function RegistryPage() {
  return <PageData load={load}>{data => <RegistryWorkspace initialProviders={data.providers} initialModels={data.models} providerDomains={data.domains} />}</PageData>;
}
