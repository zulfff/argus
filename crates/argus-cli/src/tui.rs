use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};
use reqwest::Client;
use serde::Deserialize;
use std::io;
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Deserialize, Clone, Debug)]
#[allow(dead_code)]
struct RuleItem {
    #[serde(default)]
    id: String,
    name: String,
    action: String,
    direction: String,
    #[serde(default)]
    src_cidr: Option<String>,
    #[serde(default)]
    dst_cidr: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    enabled: bool,
}

#[derive(Deserialize, Clone, Debug)]
struct StatsItem {
    packets_allowed: u64,
    packets_dropped: u64,
    active_connections: usize,
    blocked_ips: usize,
    rate_limit_buckets: usize,
}

#[derive(Deserialize, Clone, Debug)]
struct ConnItem {
    src_ip: String,
    dst_ip: String,
    state: String,
}

#[derive(Clone, Debug)]
enum TuiEvent {
    Rules(Vec<RuleItem>),
    Stats(StatsItem),
    Connections(Vec<ConnItem>),
    Tick,
}

pub async fn run_tui(api_url: String) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

    let (tx, mut rx) = mpsc::channel(100);
    let api_url_clone = api_url.clone();

    tokio::spawn(async move {
        let client = Client::new();
        loop {
            let rules = fetch_rules(&client, &api_url_clone)
                .await
                .unwrap_or_default();
            let _ = tx.send(TuiEvent::Rules(rules)).await;

            let stats = fetch_stats(&client, &api_url_clone).await;
            if let Ok(s) = stats {
                let _ = tx.send(TuiEvent::Stats(s)).await;
            }

            let conns = fetch_connections(&client, &api_url_clone)
                .await
                .unwrap_or_default();
            let _ = tx.send(TuiEvent::Connections(conns)).await;

            let _ = tx.send(TuiEvent::Tick).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });

    let mut app = TuiApp::default();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    loop {
        terminal.draw(|f| app.render(f))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press && key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }

        while let Ok(event) = rx.try_recv() {
            match event {
                TuiEvent::Rules(r) => app.rules = r,
                TuiEvent::Stats(s) => app.stats = Some(s),
                TuiEvent::Connections(c) => app.connections = c,
                TuiEvent::Tick => {}
            }
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;

    Ok(())
}

async fn fetch_rules(client: &Client, api_url: &str) -> Result<Vec<RuleItem>> {
    let resp = client
        .get(format!("{}/api/v1/rules", api_url))
        .send()
        .await?;
    Ok(resp.json().await?)
}

async fn fetch_stats(client: &Client, api_url: &str) -> Result<StatsItem> {
    let resp = client
        .get(format!("{}/api/v1/stats", api_url))
        .send()
        .await?;
    Ok(resp.json().await?)
}

async fn fetch_connections(client: &Client, api_url: &str) -> Result<Vec<ConnItem>> {
    let resp = client
        .get(format!("{}/api/v1/connections", api_url))
        .send()
        .await?;
    Ok(resp.json().await?)
}

#[derive(Default)]
struct TuiApp {
    rules: Vec<RuleItem>,
    stats: Option<StatsItem>,
    connections: Vec<ConnItem>,
}

impl TuiApp {
    fn render(&self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(7),
                Constraint::Min(0),
                Constraint::Length(10),
            ])
            .split(f.area());

        self.render_stats(f, chunks[0]);
        self.render_rules(f, chunks[1]);
        self.render_connections(f, chunks[2]);
    }

    fn render_stats(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let block = Block::default()
            .title(" Statistics ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        if let Some(stats) = &self.stats {
            let text = format!(
                "Allowed: {}  |  Dropped: {}  |  Active Connections: {}  |  Blocked IPs: {}  |  Rate Buckets: {}",
                stats.packets_allowed,
                stats.packets_dropped,
                stats.active_connections,
                stats.blocked_ips,
                stats.rate_limit_buckets,
            );
            let p = Paragraph::new(text).block(block);
            f.render_widget(p, area);
        } else {
            let p = Paragraph::new("Connecting...").block(block);
            f.render_widget(p, area);
        }
    }

    fn render_rules(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let block = Block::default()
            .title(format!(" Firewall Rules ({}) ", self.rules.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        let items: Vec<ListItem> = self
            .rules
            .iter()
            .map(|r| {
                let status = if r.enabled {
                    Span::styled(" [ON] ", Style::default().fg(Color::Green))
                } else {
                    Span::styled(" [OFF]", Style::default().fg(Color::Red))
                };

                let action_color = match r.action.as_str() {
                    "deny" => Color::Red,
                    "allow" => Color::Green,
                    _ => Color::Yellow,
                };
                let action = Span::styled(
                    format!(" {:<12}", r.action),
                    Style::default().fg(action_color),
                );

                let src = r.src_cidr.as_deref().unwrap_or("*");
                let dst = r.dst_cidr.as_deref().unwrap_or("*");
                let name = &r.name;

                let line = Line::from(vec![
                    status,
                    action,
                    Span::raw(format!(" src={:<18} dst={:<18} {}", src, dst, name)),
                ]);

                ListItem::new(line)
            })
            .collect();

        let list = List::new(items).block(block);
        f.render_widget(list, area);
    }

    fn render_connections(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let block = Block::default()
            .title(format!(" Active Connections ({}) ", self.connections.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        let text: String = if self.connections.is_empty() {
            "No active connections".into()
        } else {
            self.connections
                .iter()
                .take(5)
                .map(|c| format!("{} -> {} [{}]", c.src_ip, c.dst_ip, c.state))
                .collect::<Vec<_>>()
                .join("  |  ")
        };

        let p = Paragraph::new(text).block(block);
        f.render_widget(p, area);
    }
}
