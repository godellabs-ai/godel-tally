use anyhow::{Result, bail};
use tally_connectors::ManagedCloudScope;

use crate::{
    VendorAdapter, aws, azure, gcp,
    pull_support::{NativeCloudSnapshot, NativeNetworkPull, NativeNetworkSnapshot},
};

pub(crate) async fn pull_inventory(
    adapter: VendorAdapter,
    scope: &ManagedCloudScope,
    client: &reqwest::Client,
) -> Result<NativeCloudSnapshot> {
    match (adapter, scope) {
        (
            VendorAdapter::AwsManagedAiApi,
            ManagedCloudScope::Aws {
                region,
                static_credentials,
                ..
            },
        ) => aws::pull_inventory(client, region, static_credentials.as_ref()).await,
        (
            VendorAdapter::AzureOpenaiApi | VendorAdapter::AzureAiFoundryApi,
            ManagedCloudScope::Azure {
                subscription_id,
                account_resource_id,
                workspace_resource,
                static_credentials,
                ..
            },
        ) => {
            azure::pull_inventory(
                client,
                subscription_id,
                account_resource_id,
                workspace_resource.as_deref(),
                static_credentials.as_ref(),
            )
            .await
        }
        (
            VendorAdapter::GcpVertexAiApi,
            ManagedCloudScope::Gcp {
                project_id,
                location,
                static_credentials,
            },
        ) => gcp::pull_inventory(client, project_id, location, static_credentials.as_ref()).await,
        _ => bail!("native cloud adapter and scope do not match"),
    }
}

pub(crate) async fn pull_network(
    request: &NativeNetworkPull<'_>,
    client: &reqwest::Client,
) -> Result<NativeNetworkSnapshot> {
    match request.adapter {
        VendorAdapter::AwsCloudFlowApi | VendorAdapter::AwsNetworkMappingApi => {
            aws::pull_network(request, client).await
        }
        VendorAdapter::AzureCloudFlowApi | VendorAdapter::AzureNetworkMappingApi => {
            azure::pull_network(request, client).await
        }
        VendorAdapter::GcpCloudFlowApi | VendorAdapter::GcpNetworkMappingApi => {
            gcp::pull_network(request, client).await
        }
        _ => bail!("native cloud-network adapter is unsupported"),
    }
}
