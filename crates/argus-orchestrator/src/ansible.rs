use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tracing::{debug, error, instrument};

use argus_common::error::{ArgusError, Result};

const PLAYBOOK_TIMEOUT_SECS: u64 = 300;
const ANSIBLE_PLAYBOOK_DIR: &str = "ansible/playbooks";

#[derive(Debug, Clone)]
pub enum PlaybookResult {
    Success {
        plays: u32,
        tasks: u32,
        changed: u32,
        failed: u32,
        skipped: u32,
        duration_secs: f64,
        output: String,
    },
    Failure {
        error: String,
        output: String,
        duration_secs: f64,
    },
    DryRun {
        would_change: u32,
        tasks: u32,
        output: String,
    },
    Unreachable {
        host: String,
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct AnsibleJob {
    pub id: uuid::Uuid,
    pub playbook: String,
    pub inventory: Option<String>,
    pub extra_vars: serde_json::Value,
    pub dry_run: bool,
    pub limit_hosts: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub result: Option<PlaybookResult>,
}

pub struct AnsibleRunner {
    playbook_dir: PathBuf,
    ansible_bin: String,
    default_inventory: Option<String>,
}

impl AnsibleRunner {
    pub fn new() -> Self {
        Self {
            playbook_dir: PathBuf::from(ANSIBLE_PLAYBOOK_DIR),
            ansible_bin: "ansible-playbook".to_string(),
            default_inventory: None,
        }
    }

    pub fn with_playbook_dir(mut self, dir: PathBuf) -> Self {
        self.playbook_dir = dir;
        self
    }

    pub fn with_ansible_bin(mut self, bin: String) -> Self {
        self.ansible_bin = bin;
        self
    }

    pub fn with_inventory(mut self, inventory: String) -> Self {
        self.default_inventory = Some(inventory);
        self
    }

    #[instrument(skip(self, extra_vars))]
    pub async fn run_playbook(
        &self,
        playbook: &str,
        extra_vars: serde_json::Value,
        dry_run: bool,
    ) -> Result<PlaybookResult> {
        let job = AnsibleJob {
            id: uuid::Uuid::new_v4(),
            playbook: playbook.to_string(),
            inventory: None,
            extra_vars: extra_vars.clone(),
            dry_run,
            limit_hosts: None,
            tags: None,
            started_at: chrono::Utc::now(),
            result: None,
        };

        self.execute_job(&job).await
    }

    #[instrument(skip(self, job))]
    pub async fn execute_job(&self, job: &AnsibleJob) -> Result<PlaybookResult> {
        let playbook_path = self.playbook_dir.join(&job.playbook);
        if !playbook_path.exists() {
            return Err(ArgusError::Config(format!(
                "playbook not found: {}",
                playbook_path.display()
            )));
        }

        let start = std::time::Instant::now();
        let mut cmd = Command::new(&self.ansible_bin);

        cmd.arg(&playbook_path);
        cmd.arg("--extra-vars").arg(job.extra_vars.to_string());

        if let Some(ref inventory) = job.inventory.as_ref().or(self.default_inventory.as_ref()) {
            cmd.arg("--inventory").arg(inventory);
        }

        if job.dry_run {
            cmd.arg("--check");
            cmd.arg("--diff");
        }

        if let Some(ref hosts) = job.limit_hosts {
            cmd.arg("--limit").arg(hosts.join(","));
        }

        if let Some(ref tags) = job.tags {
            cmd.arg("--tags").arg(tags.join(","));
        }

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        debug!("Running: {:?}", cmd);

        let child = cmd.spawn().map_err(|e| {
            error!("Failed to spawn ansible-playbook: {}", e);
            ArgusError::External(format!("ansible-playbook spawn failed: {}", e))
        })?;

        let output = tokio::time::timeout(
            Duration::from_secs(PLAYBOOK_TIMEOUT_SECS),
            child.wait_with_output(),
        )
        .await
        .map_err(|_| ArgusError::External("ansible-playbook timed out after 300 seconds".into()))?
        .map_err(|e| ArgusError::External(format!("ansible-playbook IO error: {}", e)))?;

        let duration_secs = start.elapsed().as_secs_f64();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            return Ok(PlaybookResult::Failure {
                error: stderr.lines().last().unwrap_or("unknown error").to_string(),
                output: stdout,
                duration_secs,
            });
        }

        let stats = self.parse_ansible_output(&stdout);

        if job.dry_run {
            Ok(PlaybookResult::DryRun {
                would_change: stats.3,
                tasks: stats.1,
                output: stdout,
            })
        } else {
            Ok(PlaybookResult::Success {
                plays: stats.0,
                tasks: stats.1,
                changed: stats.3,
                failed: stats.2,
                skipped: stats.4,
                duration_secs,
                output: stdout,
            })
        }
    }

    fn parse_ansible_output(&self, output: &str) -> (u32, u32, u32, u32, u32) {
        let mut plays = 0u32;
        let mut tasks = 0u32;
        let mut failed = 0u32;
        let mut changed = 0u32;
        let mut skipped = 0u32;

        for line in output.lines() {
            let line = line.trim();
            if line.contains("PLAY RECAP") {
                continue;
            }
            if line.contains("ok=") {
                for part in line.split_whitespace() {
                    if part.starts_with("ok=") {
                        tasks += part.trim_start_matches("ok=").parse::<u32>().unwrap_or(0);
                    } else if part.starts_with("changed=") {
                        changed += part
                            .trim_start_matches("changed=")
                            .parse::<u32>()
                            .unwrap_or(0);
                    } else if part.starts_with("unreachable=") {
                        failed += part
                            .trim_start_matches("unreachable=")
                            .parse::<u32>()
                            .unwrap_or(0);
                    } else if part.starts_with("failed=") {
                        failed += part
                            .trim_start_matches("failed=")
                            .parse::<u32>()
                            .unwrap_or(0);
                    } else if part.starts_with("skipped=") {
                        skipped += part
                            .trim_start_matches("skipped=")
                            .parse::<u32>()
                            .unwrap_or(0);
                    }
                }
            }
            if line.starts_with("PLAY [") {
                plays += 1;
            }
        }

        (plays, tasks, failed, changed, skipped)
    }

    #[instrument(skip(self))]
    pub async fn verify_connectivity(&self, host: &str) -> Result<bool> {
        let mut cmd = Command::new(&self.ansible_bin);
        if let Some(ref inv) = self.default_inventory {
            cmd.arg("--inventory").arg(inv);
        }
        cmd.arg("-m").arg("ping");
        cmd.arg("-o");
        cmd.arg(host);

        let output = cmd
            .output()
            .await
            .map_err(|e| ArgusError::External(format!("ansible ping failed: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        Ok(stdout.contains("SUCCESS"))
    }
}

impl Default for AnsibleRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ansible_recap_line() {
        let runner = AnsibleRunner::new();
        let output = r#"
PLAY [Configure VyOS firewall] ******************************************
ok: [vyos-router-01]
changed: [vyos-router-01]
PLAY RECAP ****************************************************************
vyos-router-01 : ok=5 changed=2 unreachable=0 failed=0 skipped=1
"#;
        let (plays, tasks, failed, changed, skipped) = runner.parse_ansible_output(output);
        assert_eq!(plays, 1);
        assert_eq!(tasks, 5);
        assert_eq!(failed, 0);
        assert_eq!(changed, 2);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn test_missing_playbook() {
        let runner = AnsibleRunner::new();
        let job = AnsibleJob {
            id: uuid::Uuid::new_v4(),
            playbook: "nonexistent.yml".into(),
            inventory: None,
            extra_vars: serde_json::json!({}),
            dry_run: false,
            limit_hosts: None,
            tags: None,
            started_at: chrono::Utc::now(),
            result: None,
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(runner.execute_job(&job));
        assert!(result.is_err());
    }
}
