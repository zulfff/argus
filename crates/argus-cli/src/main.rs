mod tui;

use clap::{Parser, Subcommand};
use reqwest::Client;
use serde::Deserialize;

const DEFAULT_API_URL: &str = "http://127.0.0.1:8443";

#[derive(Parser)]
#[command(name = "argus", about = "ARGUS firewall management CLI")]
struct Cli {
    #[arg(long, default_value = DEFAULT_API_URL)]
    api_url: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(alias = "ls")]
    Rules,
    Stats,
    #[command(alias = "conn")]
    Connections,
    Block {
        ip: String,
    },
    Unblock {
        ip: String,
    },
    #[command(alias = "mon")]
    Tui,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct RuleItem {
    id: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    action: String,
    direction: String,
    #[serde(default)]
    src_cidr: Option<String>,
    #[serde(default)]
    dst_cidr: Option<String>,
    #[serde(default)]
    src_port: Option<u16>,
    #[serde(default)]
    dst_port: Option<u16>,
    #[serde(default)]
    protocol: Option<String>,
    priority: u32,
    enabled: bool,
}

#[derive(Deserialize)]
struct StatsItem {
    packets_allowed: u64,
    packets_dropped: u64,
    active_connections: usize,
    blocked_ips: usize,
    rate_limit_buckets: usize,
}

#[derive(Deserialize)]
struct ConnItem {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    state: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct JsonResponse {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    deleted: Option<String>,
    #[serde(default)]
    blocked: Option<String>,
    #[serde(default)]
    unblocked: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Commands::Tui = cli.command {
        return tui::run_tui(cli.api_url).await;
    }

    let client = Client::new();

    match cli.command {
        Commands::Tui => unreachable!(),

        Commands::Rules => {
            let resp = client
                .get(format!("{}/api/v1/rules", cli.api_url))
                .send()
                .await?;
            let rules: Vec<RuleItem> = resp.json().await?;

            if rules.is_empty() {
                println!("No rules configured.");
                return Ok(());
            }

            println!(
                "{:<5} {:<8} {:<12} {:<18} {:<18} {:<16} {:<8} {:<10}",
                "PRI", "ENABLED", "ACTION", "SRC", "DST", "PROTO", "DIR", "NAME"
            );
            println!("{}", "-".repeat(100));

            for r in &rules {
                let src = r.src_cidr.as_deref().unwrap_or("*");
                let dst = r.dst_cidr.as_deref().unwrap_or("*");
                let proto = r.protocol.as_deref().unwrap_or("any");
                let dir = &r.direction;
                let enabled = if r.enabled { "YES" } else { "NO" };
                println!(
                    "{:<5} {:<8} {:<12} {:<18} {:<18} {:<16} {:<8} {:<10}",
                    r.priority, enabled, r.action, src, dst, proto, dir, r.name
                );
            }

            println!("\nTotal: {} rules", rules.len());
        }

        Commands::Stats => {
            let resp = client
                .get(format!("{}/api/v1/stats", cli.api_url))
                .send()
                .await?;
            let stats: StatsItem = resp.json().await?;

            println!("=== ARGUS Firewall Statistics ===");
            println!("Packets Allowed:     {}", stats.packets_allowed);
            println!("Packets Dropped:     {}", stats.packets_dropped);
            println!("Active Connections:  {}", stats.active_connections);
            println!("Blocked IPs:         {}", stats.blocked_ips);
            println!("Rate Limit Buckets:  {}", stats.rate_limit_buckets);
        }

        Commands::Connections => {
            let resp = client
                .get(format!("{}/api/v1/connections", cli.api_url))
                .send()
                .await?;
            let conns: Vec<ConnItem> = resp.json().await?;

            if conns.is_empty() {
                println!("No active connections.");
                return Ok(());
            }

            println!(
                "{:<18} {:<8} {:<18} {:<8} {:<6} {:<12}",
                "SRC", "SPORT", "DST", "DPORT", "PROTO", "STATE"
            );
            println!("{}", "-".repeat(76));

            for c in &conns {
                println!(
                    "{:<18} {:<8} {:<18} {:<8} {:<6} {:<12}",
                    c.src_ip, c.src_port, c.dst_ip, c.dst_port, c.protocol, c.state
                );
            }

            println!("\nTotal: {} connections", conns.len());
        }

        Commands::Block { ip } => {
            let resp = client
                .post(format!("{}/api/v1/block", cli.api_url))
                .json(&serde_json::json!({"ip": ip}))
                .send()
                .await?;

            let body: JsonResponse = resp.json().await?;
            if let Some(err) = body.error {
                eprintln!("Error: {}", err);
            } else if let Some(blocked) = body.blocked {
                println!("Blocked: {}", blocked);
            }
        }

        Commands::Unblock { ip } => {
            let resp = client
                .delete(format!("{}/api/v1/block/{}", cli.api_url, ip))
                .send()
                .await?;

            let body: JsonResponse = resp.json().await?;
            if let Some(unblocked) = body.unblocked {
                println!("Unblocked: {}", unblocked);
            }
        }
    }

    Ok(())
}
