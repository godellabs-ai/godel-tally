//! Legacy command alias; release bundles use `tallyd rekey-for-gate`.
#[path = "../gate_rekey.rs"]
mod gate_rekey;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    gate_rekey::run().await
}
