#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("tally_upgrade=info")
        .init();
    tally_upgrade::run().await
}
