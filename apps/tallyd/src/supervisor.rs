//! Own the private databases and application as one user-service lifetime.
use std::{
    fmt::Write as _,
    fs::{File, OpenOptions},
    net::{Ipv4Addr, TcpListener},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use sqlx::{Connection, PgConnection, postgres::PgConnectOptions};
use tokio::{
    process::{Child, Command},
    time::{sleep, timeout},
};

struct Process {
    name: &'static str,
    child: Child,
}

struct Databases {
    postgres: bool,
    clickhouse: bool,
    data: PathBuf,
    pg_bin: PathBuf,
    ch_bin: PathBuf,
    pg_port: u16,
    ch_port: u16,
    pg_password: String,
    ch_password: String,
    ch_database: String,
    http: reqwest::Client,
}

fn setting(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("{key} is required; rerun the Tally installer"))
}

impl Databases {
    fn from_env() -> Result<Self> {
        let postgres = std::env::var("TALLY_POSTGRES_MODE").as_deref() == Ok("native");
        let clickhouse = std::env::var("TALLY_CLICKHOUSE_MODE").as_deref() == Ok("native");
        let ch_database =
            std::env::var("TALLY_CLICKHOUSE_DATABASE").unwrap_or_else(|_| "tally".into());
        ensure!(
            !ch_database.is_empty()
                && ch_database
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_'),
            "invalid ClickHouse database name"
        );
        Ok(Self {
            postgres,
            clickhouse,
            data: PathBuf::from(setting("TALLY_DATA_DIR")?),
            pg_bin: PathBuf::from(if postgres {
                setting("TALLY_PG_BIN")?
            } else {
                String::new()
            }),
            ch_bin: PathBuf::from(if clickhouse {
                setting("TALLY_CLICKHOUSE_BIN")?
            } else {
                String::new()
            }),
            pg_port: std::env::var("TALLY_POSTGRES_PORT")
                .unwrap_or_else(|_| "5433".into())
                .parse()?,
            ch_port: std::env::var("TALLY_CLICKHOUSE_PORT")
                .unwrap_or_else(|_| "8124".into())
                .parse()?,
            pg_password: if postgres {
                setting("TALLY_POSTGRES_PASSWORD")?
            } else {
                String::new()
            },
            ch_password: if clickhouse {
                setting("TALLY_CLICKHOUSE_PASSWORD")?
            } else {
                String::new()
            },
            ch_database,
            http: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(3))
                .build()?,
        })
    }

    async fn pg_connect(&self) -> Result<PgConnection> {
        let options = PgConnectOptions::new()
            .host("127.0.0.1")
            .port(self.pg_port)
            .username("tally")
            .password(&self.pg_password)
            .database("postgres");
        timeout(Duration::from_secs(3), PgConnection::connect_with(&options))
            .await?
            .context("private PostgreSQL is unavailable")
    }

    async fn ch_query(&self, query: &str) -> Result<()> {
        self.http
            .post(format!("http://127.0.0.1:{}/", self.ch_port))
            // A health-check connection must not hold ClickHouse open during shutdown.
            .header(reqwest::header::CONNECTION, "close")
            .header("X-ClickHouse-User", "tally")
            .header("X-ClickHouse-Key", &self.ch_password)
            .body(query.to_owned())
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    async fn health_query(&self) -> Result<()> {
        if self.postgres {
            let mut connection = self.pg_connect().await?;
            let directory: String = sqlx::query_scalar("SHOW data_directory")
                .fetch_one(&mut connection)
                .await?;
            ensure!(
                Path::new(&directory).canonicalize()?
                    == self.data.join("postgres").canonicalize()?,
                "PostgreSQL on the configured port is not this Tally instance"
            );
        }
        if self.clickhouse {
            self.ch_query("SELECT 1")
                .await
                .context("private ClickHouse is unavailable")?;
        }
        Ok(())
    }

    async fn healthy(&self) -> Result<()> {
        timeout(Duration::from_secs(6), self.health_query()).await?
    }

    async fn provision(&self) -> Result<()> {
        if self.postgres {
            let mut connection = self.pg_connect().await?;
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = 'tally')",
            )
            .fetch_one(&mut connection)
            .await?;
            if !exists {
                sqlx::query("CREATE DATABASE tally")
                    .execute(&mut connection)
                    .await?;
            }
        }
        if self.clickhouse {
            self.ch_query(&format!(
                "CREATE DATABASE IF NOT EXISTS `{}`",
                self.ch_database
            ))
            .await?;
        }
        Ok(())
    }
}

fn log_file(data: &Path, name: &str) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(data.join(format!("{name}.log")))
        .context("open private database log")
}

fn spawn(name: &'static str, command: &mut Command, log: Option<File>) -> Result<Process> {
    command.kill_on_drop(true).stdin(Stdio::null());
    if let Some(log) = log {
        command.stdout(log.try_clone()?).stderr(log);
    }
    let child = command
        .spawn()
        .with_context(|| format!("start {name}; inspect its log in TALLY_DATA_DIR"))?;
    eprintln!(
        "Tally: started {name} (PID {}).",
        child.id().unwrap_or_default()
    );
    Ok(Process { name, child })
}

fn record_children(data: &Path, processes: &[Process]) -> Result<()> {
    let mut pids = String::new();
    for process in processes {
        if let Some(pid) = process.child.id() {
            writeln!(pids, "{pid}")?;
        }
    }
    std::fs::write(data.join("supervisor.pids"), pids)?;
    Ok(())
}

fn ensure_children_stopped(data: &Path) -> Result<()> {
    let path = data.join("supervisor.pids");
    if !path.exists() {
        return Ok(());
    }
    for line in std::fs::read_to_string(&path)?.lines() {
        let pid: u32 = line.parse().context("invalid supervisor process record")?;
        ensure!(pid > 1, "invalid supervisor process ID");
        let alive = std::process::Command::new("/bin/kill")
            .args(["-0", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success();
        ensure!(
            !alive,
            "a previous Tally child process (PID {pid}) may still be running; stop that instance before continuing"
        );
    }
    std::fs::remove_file(path)?;
    Ok(())
}

fn check_processes(processes: &mut [Process]) -> Result<Option<std::process::ExitStatus>> {
    for process in processes {
        if let Some(status) = process.child.try_wait()? {
            if process.name == "application" {
                return Ok(Some(status));
            }
            bail!(
                "{} stopped unexpectedly ({status}); stopping Tally and its other private database",
                process.name
            );
        }
    }
    Ok(None)
}

async fn stop(process: &mut Process) -> Result<()> {
    if process.child.try_wait()?.is_some() {
        return Ok(());
    }
    if let Some(pid) = process.child.id() {
        eprintln!("Tally: stopping {}...", process.name);
        // PostgreSQL SIGINT requests a fast, clean shutdown, including its workers.
        let signal = if process.name == "postgres" {
            "-INT"
        } else {
            "-TERM"
        };
        let _ = Command::new("/bin/kill")
            .args([signal, &pid.to_string()])
            .status()
            .await;
        if let Ok(status) = timeout(Duration::from_secs(25), process.child.wait()).await {
            status?;
        } else {
            eprintln!(
                "Tally: {} did not stop in time; terminating it.",
                process.name
            );
            process.child.kill().await?;
        }
    }
    Ok(())
}

async fn shutdown_signal() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    tokio::select! { _ = terminate.recv() => {}, _ = interrupt.recv() => {} }
    Ok(())
}

async fn supervise(databases: &Databases, processes: &mut Vec<Process>) -> Result<()> {
    // Refuse a port collision before starting either database. Never adopt another server.
    let mut ports = Vec::new();
    for (enabled, port) in [
        (databases.postgres, databases.pg_port),
        (databases.clickhouse, databases.ch_port),
    ] {
        if enabled {
            ports.push(
                TcpListener::bind((Ipv4Addr::LOCALHOST, port)).with_context(|| {
                    format!("port {port} is already in use; choose a free Tally database port")
                })?,
            );
        }
    }
    drop(ports);
    if databases.postgres {
        processes.push(spawn(
            "postgres",
            Command::new(databases.pg_bin.join("postgres"))
                .args(["-D"])
                .arg(databases.data.join("postgres"))
                .args([
                    "-h",
                    "127.0.0.1",
                    "-p",
                    &databases.pg_port.to_string(),
                    "-k",
                    "",
                ])
                .env("LC_ALL", "en_US.UTF-8"),
            Some(log_file(&databases.data, "postgres")?),
        )?);
    }
    record_children(&databases.data, processes)?;
    if databases.clickhouse {
        processes.push(spawn(
            "clickhouse",
            Command::new(&databases.ch_bin)
                .arg("server")
                .arg(format!(
                    "--config-file={}/clickhouse.xml",
                    setting("TALLY_CONFIG_DIR")?
                ))
                // Prevent ClickHouse's own daemon/watchdog from escaping our child lifetime.
                .env("CLICKHOUSE_WATCHDOG_ENABLE", "0"),
            Some(log_file(&databases.data, "clickhouse")?),
        )?);
    }
    record_children(&databases.data, processes)?;
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        check_processes(processes)?;
        if databases.healthy().await.is_ok() {
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "private databases did not become ready in 90 seconds; inspect postgres.log and clickhouse.log"
        );
        sleep(Duration::from_millis(250)).await;
    }
    timeout(Duration::from_secs(30), databases.provision())
        .await?
        .context("prepare the private Tally databases")?;
    check_processes(processes)?;
    eprintln!("Tally: private databases are ready; starting the application.");
    processes.push(spawn(
        "application",
        &mut Command::new(std::env::current_exe()?),
        None,
    )?);
    record_children(&databases.data, processes)?;
    let mut next_health = Instant::now() + Duration::from_secs(5);
    let mut failed_health = 0;
    loop {
        if let Some(status) = check_processes(processes)? {
            ensure!(
                status.success(),
                "Tally application stopped unexpectedly ({status})"
            );
            return Ok(());
        }
        if Instant::now() >= next_health {
            if databases.healthy().await.is_err() {
                failed_health += 1;
            } else {
                failed_health = 0;
            }
            ensure!(
                failed_health < 3,
                "a private database failed three health checks; stopping Tally and its databases"
            );
            next_health = Instant::now() + Duration::from_secs(5);
        }
        sleep(Duration::from_millis(250)).await;
    }
}

pub async fn run() -> Result<()> {
    let databases = Databases::from_env()?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(databases.data.join("supervisor.lock"))?;
    lock.try_lock()
        .context("Tally is already running for this data directory; stop that instance first")?;
    ensure_children_stopped(&databases.data)?;
    let mut processes = Vec::new();
    let result = tokio::select! {
        biased;
        result = shutdown_signal() => result,
        result = supervise(&databases, &mut processes) => result,
    };
    let data = databases.data.clone();
    drop(databases); // Close supervisor-owned database connections before shutdown.
    // Always stop the application first, while its databases can still finish requests.
    let mut cleanup_error = None;
    for process in processes.iter_mut().rev() {
        if let Err(error) = stop(process).await {
            cleanup_error = Some(error);
        }
    }
    // Keep the lock inode stable across restarts. Unlinking a locked file permits
    // two concurrent starters to lock different inodes for the same data directory.
    if cleanup_error.is_none() {
        let _ = std::fs::remove_file(data.join("supervisor.pids"));
    }
    drop(lock);
    result?;
    if let Some(error) = cleanup_error {
        return Err(error);
    }
    Ok(())
}

pub fn check_stopped(data: &Path) -> Result<()> {
    let path = data.join("supervisor.lock");
    if !path.exists() {
        return Ok(());
    }
    let lock = OpenOptions::new().read(true).write(true).open(&path)?;
    lock.try_lock()
        .context("Tally's supervisor is still running")?;
    ensure_children_stopped(data)
}
