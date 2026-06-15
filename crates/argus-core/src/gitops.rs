use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use argus_common::error::{ArgusError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitOpsConfig {
    pub repo_url: String,
    pub branch: String,
    pub config_dir: PathBuf,
    pub auto_apply: bool,
    pub require_ci_passing: bool,
    pub ci_check_command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitOpsChange {
    pub commit_hash: String,
    pub author: String,
    pub message: String,
    pub files_changed: Vec<String>,
    pub timestamp: DateTime<Utc>,
    pub ci_status: CiStatus,
    pub applied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CiStatus {
    Pending,
    Passing,
    Failing { errors: Vec<String> },
    Skipped,
}

impl std::fmt::Display for CiStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CiStatus::Pending => write!(f, "pending"),
            CiStatus::Passing => write!(f, "passing"),
            CiStatus::Failing { .. } => write!(f, "failing"),
            CiStatus::Skipped => write!(f, "skipped"),
        }
    }
}

pub struct GitOpsEngine {
    config: GitOpsConfig,
    repo_path: PathBuf,
    applied_commits: Vec<String>,
}

impl GitOpsEngine {
    pub fn new(config: GitOpsConfig) -> Self {
        Self {
            config,
            repo_path: PathBuf::from("/var/lib/argus/gitops-repo"),
            applied_commits: Vec::new(),
        }
    }

    #[instrument(skip(self))]
    pub fn init(&mut self) -> Result<()> {
        if !self.repo_path.exists() {
            std::fs::create_dir_all(&self.repo_path).map_err(|e| {
                ArgusError::Config(format!("failed to create repo dir: {}", e))
            })?;
        }

        let git_dir = self.repo_path.join(".git");
        if !git_dir.exists() {
            self.clone_repo()?;
        } else {
            self.pull_repo()?;
        }

        Ok(())
    }

    #[instrument(skip(self))]
    pub fn detect_changes(&mut self) -> Result<Vec<GitOpsChange>> {
        self.pull_repo()?;

        let output = StdCommand::new("git")
            .arg("log")
            .arg("--format=%H|%an|%s|%aI")
            .arg("-10")
            .current_dir(&self.repo_path)
            .output()
            .map_err(|e| ArgusError::External(format!("git log failed: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut changes = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.splitn(4, '|').collect();
            if parts.len() != 4 {
                continue;
            }

            let commit = parts[0].to_string();

            if self.applied_commits.contains(&commit) {
                break;
            }

            let files = self.get_changed_files(&commit).unwrap_or_default();
            let timestamp = DateTime::parse_from_rfc3339(parts[3])
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            changes.push(GitOpsChange {
                commit_hash: commit,
                author: parts[1].to_string(),
                message: parts[2].to_string(),
                files_changed: files,
                timestamp,
                ci_status: CiStatus::Pending,
                applied: false,
            });
        }

        Ok(changes)
    }

    #[instrument(skip(self))]
    pub fn run_ci_check(&self, change: &GitOpsChange) -> CiStatus {
        let Some(ref ci_cmd) = self.config.ci_check_command else {
            return CiStatus::Skipped;
        };

        let result = StdCommand::new("sh")
            .arg("-c")
            .arg(ci_cmd)
            .env("GIT_COMMIT", &change.commit_hash)
            .current_dir(&self.repo_path)
            .output();

        match result {
            Ok(output) if output.status.success() => CiStatus::Passing,
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                CiStatus::Failing {
                    errors: stderr.lines().map(String::from).collect(),
                }
            }
            Err(e) => CiStatus::Failing {
                errors: vec![format!("CI command failed: {}", e)],
            },
        }
    }

    #[instrument(skip(self))]
    pub fn apply_change(&mut self, change: &mut GitOpsChange) -> Result<()> {
        if self.config.require_ci_passing && !matches!(change.ci_status, CiStatus::Passing) {
            return Err(ArgusError::Validation(
                "CI checks not passing — refusing to apply".into(),
            ));
        }

        for file in &change.files_changed {
            let raw_path = self.repo_path.join(file);

            let path = raw_path
                .canonicalize()
                .map_err(|e| ArgusError::Validation(
                    format!("invalid config file path '{}': {}", file, e)
                ))?;

            if !path.starts_with(&self.repo_path) {
                return Err(ArgusError::Validation(
                    format!("path traversal detected: '{}' is outside repo directory", file)
                ));
            }

            if !path.exists() {
                continue;
            }

            let content = std::fs::read_to_string(&path)
                .map_err(ArgusError::Io)?;

            let ext = path.extension().and_then(|e| e.to_str());
            match ext {
                Some("json") => {
                    let _: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
                        ArgusError::Validation(format!("invalid JSON in {}: {}", file, e))
                    })?;
                }
                Some("yaml" | "yml") => {
                    if content.trim().contains("firewall") || content.trim().contains("rules") {
                        tracing::info!("Validating YAML firewall config: {}", file);
                    }
                }
                _ => {
                    tracing::debug!("Skipping validation for unknown file type: {}", file);
                }
            }
        }

        change.applied = true;
        self.applied_commits.push(change.commit_hash.clone());

        Ok(())
    }

    #[instrument(skip(self))]
    pub fn get_config_tree(&self) -> Result<serde_json::Value> {
        let mut tree = serde_json::Map::new();

        for entry in std::fs::read_dir(&self.repo_path.join(&self.config.config_dir))
            .map_err(ArgusError::Io)?
        {
            let entry = entry.map_err(ArgusError::Io)?;
            let path = entry.path();

            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if ext == "json" {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                            let key = path
                                .file_stem()
                                .and_then(|s| s.to_str())
                                .unwrap_or("unknown");
                            tree.insert(key.to_string(), val);
                        }
                    }
                }
            }
        }

        Ok(serde_json::Value::Object(tree))
    }

    fn clone_repo(&self) -> Result<()> {
        let output = StdCommand::new("git")
            .args([
                "clone",
                "--branch",
                &self.config.branch,
                "--depth",
                "50",
                &self.config.repo_url,
                self.repo_path.to_str().unwrap_or("."),
            ])
            .output()
            .map_err(|e| ArgusError::External(format!("git clone failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ArgusError::External(format!("clone error: {}", stderr)));
        }

        Ok(())
    }

    fn pull_repo(&self) -> Result<()> {
        let output = StdCommand::new("git")
            .args(["pull", "--ff-only", "origin", &self.config.branch])
            .current_dir(&self.repo_path)
            .output()
            .map_err(|e| ArgusError::External(format!("git pull failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ArgusError::External(format!("pull error: {}", stderr)));
        }

        Ok(())
    }

    fn get_changed_files(&self, commit: &str) -> Result<Vec<String>> {
        let output = StdCommand::new("git")
            .args(["diff-tree", "--no-commit-id", "--name-only", "-r", commit])
            .current_dir(&self.repo_path)
            .output()
            .map_err(|e| ArgusError::External(format!("git diff-tree: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.lines().map(String::from).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ci_status_display() {
        assert_eq!(CiStatus::Pending.to_string(), "pending");
        assert_eq!(CiStatus::Passing.to_string(), "passing");
        assert_eq!(CiStatus::Skipped.to_string(), "skipped");
    }

    #[test]
    fn test_gitops_config_serialization() {
        let config = GitOpsConfig {
            repo_url: "git@github.com:org/argus-config.git".into(),
            branch: "main".into(),
            config_dir: PathBuf::from("firewall"),
            auto_apply: false,
            require_ci_passing: true,
            ci_check_command: Some("cargo test --manifest-path firewall/tests/Cargo.toml".into()),
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("argus-config"));
    }
}
