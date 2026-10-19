//! Re-encrypt restored Tally connector credentials before Gate's worker starts.
//! The command reads secrets from local environment files and never prints them.
use anyhow::{Context, Result, bail};
use sqlx::{PgPool, Row};
use std::{env, fs, path::Path};
use tally_config::SecretCipher;
use uuid::Uuid;

fn env_value(path: &Path, name: &str) -> Result<String> {
    let contents = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let value = contents
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{name} is missing from {}", path.display()))?;
    Ok(value.to_owned())
}

pub async fn run() -> Result<()> {
    let source_env =
        env::var("TALLY_UPGRADE_SOURCE_ENV").context("TALLY_UPGRADE_SOURCE_ENV is required")?;
    let gate_env =
        env::var("TALLY_UPGRADE_GATE_ENV").context("TALLY_UPGRADE_GATE_ENV is required")?;
    let port: u16 = env::var("TALLY_IMPORT_PG_PORT")
        .unwrap_or_else(|_| "55432".into())
        .parse()
        .context("TALLY_IMPORT_PG_PORT must be a TCP port")?;
    let source_key = env::var("TALLY_SECRET_KEY")
        .or_else(|_| env_value(Path::new(&source_env), "TALLY_SECRET_KEY"))?;
    let source =
        SecretCipher::from_hex(&source_key).context("invalid source Tally encryption key")?;
    let gate_secret = env_value(Path::new(&gate_env), "JWT_SECRET")?;
    let target = SecretCipher::from_host_secret(gate_secret.as_bytes());
    let password = env_value(Path::new(&gate_env), "POSTGRES_PASSWORD")?;
    let mut url = url::Url::parse(&format!("postgres://ggate@127.0.0.1:{port}/ggate"))?;
    url.set_password(Some(&password))
        .map_err(|()| anyhow::anyhow!("invalid Gate database password"))?;
    let pool = PgPool::connect(url.as_str())
        .await
        .context("connect staged Gate database")?;
    let tally_table: bool = sqlx::query_scalar("SELECT to_regclass('connector_jobs') IS NOT NULL")
        .fetch_one(&pool)
        .await?;
    if !tally_table {
        bail!("Gate database does not contain restored Tally connector jobs");
    }
    sqlx::query("CREATE TABLE IF NOT EXISTS tally_upgrade_rekeyed_jobs (job_id UUID PRIMARY KEY)")
        .execute(&pool)
        .await?;

    let mut cursor = Uuid::nil();
    let mut changed = 0_u64;
    loop {
        let rows = sqlx::query("SELECT job_id, secret_nonce, secret_ciphertext FROM connector_jobs WHERE job_id > $1 AND secret_ciphertext IS NOT NULL ORDER BY job_id LIMIT 100")
            .bind(cursor).fetch_all(&pool).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            let id: Uuid = row.get("job_id");
            cursor = id;
            let mut tx = pool.begin().await?;
            let done: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM tally_upgrade_rekeyed_jobs WHERE job_id=$1)",
            )
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
            if done {
                tx.commit().await?;
                continue;
            }
            let nonce: Vec<u8> = row.get("secret_nonce");
            let ciphertext: Vec<u8> = row.get("secret_ciphertext");
            let plaintext = source.decrypt(&nonce, &ciphertext).with_context(|| {
                format!("cannot decrypt connector job {id}; check the source key")
            })?;
            let (new_nonce, new_ciphertext) = target
                .encrypt(&plaintext)
                .context("re-encrypt connector credentials for Gate")?;
            sqlx::query("UPDATE connector_jobs SET secret_nonce=$2, secret_ciphertext=$3, lease_owner=NULL, lease_until=NULL WHERE job_id=$1")
                .bind(id).bind(new_nonce).bind(new_ciphertext)
                .execute(&mut *tx).await?;
            sqlx::query("INSERT INTO tally_upgrade_rekeyed_jobs(job_id) VALUES ($1)")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            changed += 1;
        }
    }
    println!("Re-encrypted {changed} Tally connector jobs for Gate.");
    Ok(())
}
