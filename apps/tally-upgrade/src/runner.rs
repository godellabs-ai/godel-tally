use crate::ApiError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct Action {
    pub id: String,
    pub title: String,
    pub description: String,
    pub risk: String,
    pub executable: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub timeout_seconds: u64,
    pub effects: Vec<String>,
    pub verification: String,
    pub rollback: String,
    #[serde(default)]
    pub docker_host: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Plan {
    pub id: String,
    pub action: Action,
    pub digest: String,
    pub source_digest: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub target: String,
    pub status: String,
    pub output: String,
    pub exit_code: Option<i32>,
    pub completed_at: Option<DateTime<Utc>>,
}

fn executable(name: &str) -> String {
    if name == "ggate" {
        return format!(
            "{}/.local/bin/ggate",
            std::env::var("HOME").unwrap_or_default()
        );
    }
    let paths = match name {
        "docker" => vec![
            "/opt/homebrew/bin/docker",
            "/usr/local/bin/docker",
            "/usr/bin/docker",
        ],
        "make" => vec!["/usr/bin/make"],
        _ => vec!["/usr/bin/uname"],
    };
    paths
        .iter()
        .find(|p| Path::new(p).is_file())
        .unwrap_or(&paths[0])
        .to_string()
}
fn local_docker_host() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    let sockets = [
        format!("{home}/.colima/default/docker.sock"),
        format!("{home}/.docker/run/docker.sock"),
        "/var/run/docker.sock".into(),
    ];
    let socket = sockets
        .iter()
        .find(|p| Path::new(p).exists())
        .unwrap_or(&sockets[2]);
    format!("unix://{socket}")
}
pub fn catalog(gate: &Path) -> Vec<Action> {
    let cwd = gate.join("deploy/ggate-console").display().to_string();
    let create = |id: &str,
                  title: &str,
                  description: &str,
                  risk: &str,
                  exe: &str,
                  args: Vec<&str>,
                  timeout,
                  effects: Vec<&str>,
                  verification: &str,
                  rollback: &str| Action {
        id: id.into(),
        title: title.into(),
        description: description.into(),
        risk: risk.into(),
        executable: executable(exe),
        args: args.into_iter().map(str::to_owned).collect(),
        cwd: cwd.clone(),
        timeout_seconds: timeout,
        effects: effects.into_iter().map(str::to_owned).collect(),
        verification: verification.into(),
        rollback: rollback.into(),
        docker_host: if matches!(exe, "docker" | "make") {
            local_docker_host()
        } else {
            String::new()
        },
    };
    vec![
        create(
            "host-check",
            "Check this host",
            "Identify the operating system and architecture.",
            "Read only",
            "uname",
            vec!["-sm"],
            10,
            vec!["Read OS and architecture; no files or settings changed."],
            "A local command receipt reports the actual OS and architecture.",
            "No changes to undo.",
        ),
        create(
            "docker-check",
            "Check Docker availability",
            "Check that the local Docker engine is reachable.",
            "Read only",
            "docker",
            vec![
                "info",
                "--format",
                "{{.ServerVersion}} {{.OSType}} {{.Architecture}}",
            ],
            20,
            vec!["Contact the configured local Docker engine; no containers are created."],
            "Docker reports its version and platform. This does not establish Gate readiness.",
            "No changes to undo.",
        ),
        create(
            "gate-validate",
            "Validate Gate configuration",
            "Validate the existing Compose configuration without exposing its secret values.",
            "Read only",
            "docker",
            vec!["compose", "-f", "docker-compose.yml", "config", "--quiet"],
            30,
            vec!["Read the Gate Compose file and local environment configuration."],
            "Compose accepts the configuration; services have not been installed.",
            "No changes to undo.",
        ),
        create(
            "gate-start",
            "Deploy the Gate console",
            "Run the checkout's reviewed console bring-up workflow on this host.",
            "Changes this host",
            "make",
            vec!["up"],
            1800,
            vec![
                "Build/download agent and collector artifacts, including release URLs configured by Gate.",
                "Generate local TLS certificates if absent; build images; create Docker networks and persistent volumes.",
                "Start the console API, worker, databases, private artifact storage, web UI and TLS router.",
                "Seed private artifact storage. This source-checkout workflow is not a signed production release guarantee.",
                "Endpoint enrollment and collector installation remain separate actions; this does not protect every discovered agent.",
            ],
            "Inspect service health next, then enroll a chosen endpoint and run harmless enforcement fixtures. Installer success alone is not proof of prevention.",
            "Use the reviewed Stop console action. It preserves data volumes; source downloads and generated artifacts remain.",
        ),
        create(
            "gate-status",
            "Inspect Gate services",
            "Show actual status and health of this Compose deployment.",
            "Read only",
            "docker",
            vec![
                "compose",
                "-f",
                "docker-compose.yml",
                "ps",
                "--format",
                "json",
            ],
            30,
            vec!["Read container status; does not install or restart services."],
            "Review each component's health and then verify the authenticated console, enrollment and policy fixtures.",
            "No changes to undo.",
        ),
        create(
            "agent-doctor",
            "Check enrolled endpoint",
            "Run the installed Gate CLI's setup-health checks.",
            "Read only",
            "ggate",
            vec!["doctor"],
            30,
            vec![
                "Inspect the installed local Gate agent and hook configuration.",
                "Requires enrollment and installation through the console's native workflow first.",
            ],
            "Review every setup check; warnings and failed checks require follow-up.",
            "No changes to undo.",
        ),
        create(
            "agent-self-test",
            "Exercise policy fixtures",
            "Run Gate's built-in harmless local policy and detector fixtures.",
            "Local diagnostic",
            "ggate",
            vec!["self-test", "--json"],
            60,
            vec![
                "Evaluate built-in synthetic fixtures using the installed CLI's local evaluation pipeline.",
                "This is not an end-to-end hook, network delivery, or console audit test.",
            ],
            "Review all fixture outcomes, then separately exercise the selected integration and confirm the corresponding console event.",
            "No enforcement settings are changed.",
        ),
        create(
            "gate-stop",
            "Stop the Gate console",
            "Stop and remove the Compose service containers and network, preserving data volumes.",
            "Service interruption",
            "docker",
            vec!["compose", "-f", "docker-compose.yml", "down"],
            120,
            vec![
                "Interrupt this Gate console deployment.",
                "Remove its service containers and network; retain named volumes and downloaded artifacts.",
                "Existing endpoint behavior depends on its configured offline policy.",
            ],
            "The selected Compose project has no running service containers.",
            "A new approved Deploy console action can restart it with retained data.",
        ),
    ]
}

fn source_digest(gate: &Path) -> Result<String, ApiError> {
    let root = gate.join("deploy/ggate-console");
    if !root.is_dir() {
        return Err(ApiError::bad_request(
            "The configured Gate checkout has no console deployment directory.",
        ));
    }
    fn visit(path: &Path, root: &Path, hash: &mut Sha256) -> std::io::Result<()> {
        let mut entries = std::fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|e| e.path());
        for e in entries {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if matches!(
                name.as_ref(),
                "node_modules" | ".git" | "certs" | "target" | "dist"
            ) {
                continue;
            }
            let p = e.path();
            let meta = std::fs::symlink_metadata(&p)?;
            if meta.file_type().is_symlink() {
                return Err(std::io::Error::other(
                    "Deployment tree contains a symlink; review it manually.",
                ));
            }
            if meta.is_dir() {
                visit(&p, root, hash)?;
            } else if meta.is_file() {
                if meta.len() > 5_000_000 {
                    return Err(std::io::Error::other("Oversized deployment input"));
                }
                hash.update(
                    p.strip_prefix(root)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .as_bytes(),
                );
                hash.update([0]);
                hash.update(std::fs::read(&p)?);
                hash.update([0]);
            }
        }
        Ok(())
    }
    let mut hash = Sha256::new();
    visit(&root, &root, &mut hash).map_err(|_| {
        ApiError::bad_request(
            "Cannot safely fingerprint the Gate deployment files. Review the local checkout.",
        )
    })?;
    Ok(hex::encode(hash.finalize()))
}
pub fn preview(gate: &Path, id: &str) -> Result<Plan, ApiError> {
    let mut action = catalog(gate)
        .into_iter()
        .find(|a| a.id == id)
        .ok_or_else(|| {
            ApiError::bad_request("Unknown action. Arbitrary commands are not supported.")
        })?;
    let source = if id.starts_with("agent-") {
        action.cwd = gate.parent().unwrap_or(gate).display().to_string();
        let bytes=std::fs::read(&action.executable).map_err(|_|ApiError::bad_request("Gate CLI is not installed at ~/.local/bin/ggate. Enroll and install one endpoint from the Gate console first."))?;
        hex::encode(Sha256::digest(bytes))
    } else if id == "host-check" || id == "docker-check" {
        action.cwd = gate.parent().unwrap_or(gate).display().to_string();
        "host-diagnostic".into()
    } else {
        source_digest(gate)?
    };
    let target = format!(
        "{} / {} · Docker: {}",
        std::env::consts::OS,
        gate.canonicalize()
            .unwrap_or_else(|_| gate.to_path_buf())
            .display(),
        if action.docker_host.is_empty() {
            "not used"
        } else {
            &action.docker_host
        }
    );
    let created = Utc::now();
    let plan_id = crate::random_token();
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&(&plan_id, &action, &source, &target)).unwrap_or_default(),
    ));
    Ok(Plan {
        id: plan_id,
        action,
        digest,
        source_digest: source,
        created_at: created,
        expires_at: created + chrono::Duration::minutes(5),
        target,
        status: "awaiting_approval".into(),
        output: String::new(),
        exit_code: None,
        completed_at: None,
    })
}
pub fn validate(plan: &Plan, digest: &str, gate: &Path) -> Result<(), ApiError> {
    if plan.status != "awaiting_approval" {
        return Err(ApiError::conflict(
            "This approval has already been used or cancelled.",
        ));
    }
    if plan.expires_at < Utc::now() || !crate::secret_eq(&plan.digest, digest) {
        return Err(ApiError::conflict(
            "Approval expired or does not match the reviewed action.",
        ));
    }
    let current = preview(gate, &plan.action.id)?;
    if current.source_digest != plan.source_digest
        || current.target != plan.target
        || serde_json::to_value(&current.action).ok() != serde_json::to_value(&plan.action).ok()
    {
        return Err(ApiError::conflict(
            "Deployment inputs or target changed. Review a fresh plan.",
        ));
    }
    Ok(())
}
async fn collect<R: AsyncRead + Unpin>(mut input: R) -> String {
    let mut kept = Vec::new();
    let mut b = [0_u8; 4096];
    let mut truncated = false;
    while let Ok(n) = input.read(&mut b).await {
        if n == 0 {
            break;
        }
        let take = n.min(64000_usize.saturating_sub(kept.len()));
        kept.extend_from_slice(&b[..take]);
        truncated |= take < n;
    }
    let mut s = String::from_utf8_lossy(&kept).to_string();
    if truncated {
        s.push_str("\n[Output truncated at 64 KB]");
    }
    s
}
pub async fn execute(plan: &Plan, cancel: Arc<AtomicBool>) -> (String, Option<i32>, String) {
    let mut cmd = Command::new(&plan.action.executable);
    cmd.args(&plan.action.args).current_dir(&plan.action.cwd)
        .env_clear().env("PATH",format!("{}/.cargo/bin:{}/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",std::env::var("HOME").unwrap_or_default(),std::env::var("HOME").unwrap_or_default()))
        .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).kill_on_drop(true);
    // Deliberate small environment; provider credentials are never inherited.
    for name in ["HOME", "USER", "TMPDIR"] {
        if let Ok(v) = std::env::var(name) {
            cmd.env(name, v);
        }
    }
    if !plan.action.docker_host.is_empty() {
        cmd.env("DOCKER_HOST", &plan.action.docker_host);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.as_std_mut().process_group(0);
    }
    let mut child=match cmd.spawn(){Ok(c)=>c,Err(_)=>return("failed".into(),None,"Could not start the reviewed executable. Check its installation and working directory.".into())};
    let pid = child.id();
    let out = tokio::spawn(collect(child.stdout.take().expect("piped stdout")));
    let err = tokio::spawn(collect(child.stderr.take().expect("piped stderr")));
    let interrupted = async {
        loop {
            if cancel.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    let (status, code) = tokio::select! {
        r=child.wait()=>match r {Ok(s)=>(if s.success(){"succeeded"}else{"failed"}.into(),s.code()),Err(_)=>("uncertain".into(),None)},
        _=tokio::time::sleep(Duration::from_secs(plan.action.timeout_seconds))=>("timed_out".into(),None),
        _=interrupted=>("cancelled".into(),None),
    };
    // SAFETY: the child was started in its own process group. A negative child PID
    // signals only that group, cleaning up descendants that could hold output pipes open.
    #[cfg(unix)]
    if let Some(pid) = pid {
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
    if code.is_none() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    let stdout = out.await.unwrap_or_default();
    let stderr = err.await.unwrap_or_default();
    let output = format!("{stdout}\n{stderr}");
    (status, code, redact_output(&output))
}
pub fn redact_output(value: &str) -> String {
    value
        .lines()
        .map(|l| {
            let lower = l.to_lowercase();
            if [
                "password",
                "api_key",
                "api-key",
                "authorization:",
                "registration key",
                "private key",
                "x-godel-key",
                "jwt_secret",
                "postgres_password",
                "secret=",
                "token=",
                "gg_",
                "sk-",
            ]
            .iter()
            .any(|w| lower.contains(w))
            {
                "[Sensitive output line redacted]"
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub fn journal(dir: &Path, plan: &Plan) -> Result<(), ApiError> {
    let path = dir.join(format!("action-{}.json", plan.id));
    let tmp = path.with_extension("tmp");
    std::fs::write(
        &tmp,
        serde_json::to_vec_pretty(plan).map_err(|_| ApiError::internal())?,
    )
    .map_err(|_| ApiError::internal())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| ApiError::internal())?;
    }
    std::fs::File::open(&tmp)
        .and_then(|f| f.sync_all())
        .map_err(|_| ApiError::internal())?;
    std::fs::rename(tmp, path).map_err(|_| ApiError::internal())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_changed_deployment_file_invalidates_approval() {
        let root = std::env::temp_dir().join(crate::random_token());
        let deployment = root.join("deploy/ggate-console");
        std::fs::create_dir_all(&deployment).unwrap();
        std::fs::write(deployment.join("Makefile"), "up: old-input").unwrap();
        let plan = preview(&root, "gate-start").unwrap();
        std::fs::write(deployment.join("Makefile"), "up: changed-input").unwrap();
        assert!(validate(&plan, &plan.digest, &root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn cancellation_terminates_the_child_process() {
        let mut plan = preview(Path::new("/tmp"), "host-check").unwrap();
        plan.action.executable = "/bin/sleep".into();
        plan.action.args = vec!["20".into()];
        let cancel = Arc::new(AtomicBool::new(true));
        let result = tokio::time::timeout(Duration::from_secs(3), execute(&plan, cancel))
            .await
            .unwrap();
        assert_eq!(result.0, "cancelled");
        assert_eq!(result.1, None);
    }
    #[test]
    fn stale_changed_and_replayed_grants_are_rejected() {
        let root = std::path::PathBuf::from("/tmp");
        let mut p = preview(&root, "host-check").unwrap();
        assert!(validate(&p, &p.digest, &root).is_ok());
        assert!(validate(&p, "tampered", &root).is_err());
        p.status = "running".into();
        assert!(validate(&p, &p.digest, &root).is_err());
        p.status = "awaiting_approval".into();
        p.expires_at = Utc::now() - chrono::Duration::seconds(1);
        assert!(validate(&p, &p.digest, &root).is_err());
    }
    #[test]
    fn arbitrary_commands_are_not_in_catalog() {
        assert!(preview(Path::new("/tmp"), "rm -rf /").is_err());
    }
    #[test]
    fn common_secret_lines_are_redacted() {
        assert_eq!(
            redact_output("ok\nAPI_KEY=private\npassword: private"),
            "ok\n[Sensitive output line redacted]\n[Sensitive output line redacted]"
        );
    }
}
