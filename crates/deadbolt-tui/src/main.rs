//! deadbolt-tui: the same features as the GUI, minus the tray, over the same
//! D-Bus API. Run it with sudo over SSH; polkit lets root straight through.
#![forbid(unsafe_code)]

use deadbolt_client::{Client, Signal};
use deadbolt_common::types::*;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::border;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Row, Table, Tabs, Wrap,
};
use ratatui::{DefaultTerminal, Frame};
use serde_json::Value;
use std::time::{Duration, Instant};

const TABS: [&str; 8] = [
    "Dashboard",
    "Scan",
    "Protection",
    "Quarantine",
    "Network",
    "Tools",
    "History",
    "Settings",
];

const ASCII: border::Set = border::Set {
    top_left: "+",
    top_right: "+",
    bottom_left: "+",
    bottom_right: "+",
    vertical_left: "|",
    vertical_right: "|",
    horizontal_top: "-",
    horizontal_bottom: "-",
};

#[derive(Default)]
struct Input {
    active: bool,
    text: String,
}

#[derive(Default)]
struct State {
    tab: usize,
    ascii: bool,
    help: bool,
    msg: String,
    status: Option<Status>,
    progress: Option<ScanProgress>,
    last_summary: Option<ScanSummary>,
    job: Option<String>,
    quarantine: Vec<QuarantineItem>,
    apps: Vec<NetApp>,
    history: Vec<HistoryEvent>,
    reqs: Option<RequirementsReport>,
    settings: Option<deadbolt_common::Settings>,
    incidents: Vec<Incident>,
    frozen: Vec<Incident>,
    tool_out: Vec<String>,
    list: ListState,
    input: Input,
    browse: Option<(String, Vec<String>)>,
    down: bool,
    quit: bool,
}

impl State {
    fn block<'a>(&self, title: &'a str) -> Block<'a> {
        let b = Block::default().borders(Borders::ALL).title(title);
        if self.ascii { b.border_set(ASCII) } else { b }
    }
}

fn level_color(l: &Level) -> Color {
    match l {
        Level::Green => Color::Green,
        Level::Amber => Color::Yellow,
        Level::Red => Color::Red,
    }
}

fn when(t: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(t)
        .ok()
        .and_then(|d| {
            d.format(&time::macros::format_description!(
                "[year]-[month]-[day] [hour]:[minute] UTC"
            ))
            .ok()
        })
        .unwrap_or_default()
}

async fn refresh(c: &Client, s: &mut State) {
    match c.status().await {
        Ok(st) => {
            s.status = Some(st);
            s.down = false;
        }
        Err(e) => {
            s.down = e.daemon_down();
            s.msg = e.to_string();
            return;
        }
    }
    s.frozen = c.frozen().await.unwrap_or_default();
    match s.tab {
        2 => {
            s.settings = c.settings().await.ok();
            s.incidents = c.incidents().await.unwrap_or_default();
        }
        3 => match c.quarantine_list().await {
            Ok(q) => s.quarantine = q,
            Err(e) => s.msg = e.to_string(),
        },
        4 => s.apps = c.net_apps().await.unwrap_or_default(),
        6 => {
            s.history = c
                .history(&serde_json::json!({"limit": 300}))
                .await
                .unwrap_or_default()
        }
        7 => {
            s.reqs = c.requirements(false).await.ok();
            s.settings = c.settings().await.ok();
        }
        _ => {}
    }
}

fn list_len(s: &State) -> usize {
    match s.tab {
        3 => s.quarantine.len(),
        4 => s.apps.len(),
        6 => s.history.len(),
        _ => s.browse.as_ref().map(|b| b.1.len()).unwrap_or(0),
    }
}

fn read_dir(dir: &str) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    if e.file_type().is_ok_and(|t| t.is_dir()) {
                        format!("{n}/")
                    } else {
                        n
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v.insert(0, "../".into());
    v
}

fn draw(f: &mut Frame, s: &mut State) {
    let [top, banner, body, foot] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .areas(f.area());

    let titles: Vec<Line> = TABS
        .iter()
        .enumerate()
        .map(|(i, t)| Line::from(format!("{} {t}", i + 1)))
        .collect();
    f.render_widget(
        Tabs::new(titles)
            .select(s.tab)
            .block(s.block("Deadbolt"))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        top,
    );

    let (text, color) = if s.down {
        (
            "deadboltd is not running. Start it with: sudo systemctl start deadboltd".to_string(),
            Color::Red,
        )
    } else if let Some(st) = &s.status {
        (st.reason.clone(), level_color(&st.level))
    } else {
        ("Connecting...".into(), Color::Reset)
    };
    f.render_widget(
        Paragraph::new(text)
            .style(Style::default().fg(color).add_modifier(Modifier::BOLD))
            .block(s.block("Status")),
        banner,
    );

    match s.tab {
        0 => dashboard(f, s, body),
        1 => scan(f, s, body),
        2 => protection(f, s, body),
        3 => quarantine(f, s, body),
        4 => network(f, s, body),
        5 => tools(f, s, body),
        6 => history(f, s, body),
        _ => settings(f, s, body),
    }

    let keys = match s.tab {
        0 => "s quick scan  u update signatures  p pause 1h  r resume",
        1 => "e type a path  b browse  Enter start  Q/H/F presets  space pause  c cancel",
        2 => "t real-time on/off  g shield on/off",
        3 => "Up/Down select  r restore  x delete",
        4 => "Up/Down select  b block/unblock  l allow local network",
        5 => "e EICAR test  w shield test  k rkhunter  c chkrootkit  l lynis  i integrity",
        6 => "Up/Down scroll",
        _ => "d re-check requirements",
    };
    let foot_text = if s.msg.is_empty() {
        format!("{keys}  | 1-8 or Tab switch  ? help  q quit")
    } else {
        s.msg.clone()
    };
    f.render_widget(
        Paragraph::new(foot_text).style(Style::default().add_modifier(Modifier::DIM)),
        foot,
    );

    if let Some(inc) = s.frozen.first() {
        let area = centered(f.area(), 70, 14);
        f.render_widget(Clear, area);
        let mut lines = vec![
            Line::from(Span::styled(
                "Ransomware shield froze an app",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )),
            Line::from(format!(
                "App: {}   PID {}   User {}",
                inc.app, inc.pid, inc.user
            )),
            Line::from(format!("Executable: {}", inc.exe)),
            Line::from(format!("Score {}: {}", inc.score, inc.signals.join("; "))),
            Line::from(format!(
                "{} files touched, first: {}",
                inc.files.len(),
                inc.files.first().cloned().unwrap_or_default()
            )),
        ];
        if let Some(sig) = &inc.binary_signature {
            lines.push(Line::from(format!("ClamAV knows this binary: {sig}")));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(
            "It stays frozen until you choose:  K kill   A allow once   L always allow",
        ));
        f.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: true })
                .block(s.block("Frozen")),
            area,
        );
    } else if s.help {
        let area = centered(f.area(), 64, 16);
        f.render_widget(Clear, area);
        let lines: Vec<Line> = [
            "1-8, Tab, Shift+Tab   switch tabs",
            "q                     quit the TUI (the daemon keeps running)",
            "?                     this help",
            "Dashboard: s quick scan, u update, p pause 1 hour, r resume",
            "Scan: e type path, b file browser, Enter start, Q/H/F preset",
            "      space pause/resume, c cancel",
            "Protection: t real-time on/off, g shield on/off",
            "Quarantine: r restore to original path, x delete",
            "Network: b block/unblock, l allow local network",
            "Tools: e EICAR, w shield test, k/c/l/i run tools",
            "Frozen app dialog: K kill, A allow once, L always allow",
            "--ascii               plain ASCII borders",
        ]
        .iter()
        .map(|l| Line::from(*l))
        .collect();
        f.render_widget(Paragraph::new(lines).block(s.block("Keys")), area);
    }
}

fn centered(r: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(r.width);
    let h = h.min(r.height);
    Rect {
        x: r.x + (r.width - w) / 2,
        y: r.y + (r.height - h) / 2,
        width: w,
        height: h,
    }
}

fn dashboard(f: &mut Frame, s: &State, area: Rect) {
    let Some(st) = &s.status else { return };
    let tile = |t: &str, v: String| Row::new(vec![t.to_string(), v]);
    let rows = vec![
        tile(
            "Real-time",
            format!(
                "{} ({})",
                if st.realtime.running { "on" } else { "off" },
                st.realtime.mode
            ),
        ),
        tile(
            "Ransomware Shield",
            format!(
                "{}, {} canaries, {} unprotected",
                if st.shield.enabled && st.shield.running {
                    "on"
                } else {
                    "off"
                },
                st.shield.canaries,
                st.shield.unprotected.len()
            ),
        ),
        tile(
            "Signatures",
            format!(
                "{} days old, engine {}",
                st.signatures
                    .age_days
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "?".into()),
                st.signatures.engine
            ),
        ),
        tile(
            "Last scan",
            st.last_scan
                .as_ref()
                .map(|l| {
                    format!(
                        "{} on {}, {} threats",
                        l.profile,
                        when(l.finished),
                        l.detections.len()
                    )
                })
                .unwrap_or_else(|| "never".into()),
        ),
        tile("Quarantine", format!("{} items", st.quarantine_count)),
        tile("Network blocks", format!("{} apps", st.network_blocks)),
    ];
    f.render_widget(
        Table::new(rows, [Constraint::Length(20), Constraint::Min(10)]).block(s.block("Overview")),
        area,
    );
}

fn scan(f: &mut Frame, s: &mut State, area: Rect) {
    let [inp, prog, res] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(3),
    ])
    .areas(area);
    let t = if s.input.active {
        format!("{}_", s.input.text)
    } else if s.input.text.is_empty() {
        "press e to type a path, b to browse".into()
    } else {
        s.input.text.clone()
    };
    f.render_widget(Paragraph::new(t).block(s.block("Path")), inp);
    match &s.progress {
        Some(p) if p.total > 0 => {
            let ratio = (p.done as f64 / p.total as f64).clamp(0.0, 1.0);
            f.render_widget(
                Gauge::default()
                    .ratio(ratio)
                    .label(format!(
                        "{}/{}  {} found  {:?}  {}",
                        p.done, p.total, p.found, p.state, p.current
                    ))
                    .block(s.block("Progress")),
                prog,
            );
        }
        Some(p) => f.render_widget(
            Paragraph::new(format!(
                "{:?}: {} found{}",
                p.state,
                p.found,
                if p.fallback {
                    "  (clamd down, using clamscan, slow)"
                } else {
                    ""
                }
            ))
            .block(s.block("Progress")),
            prog,
        ),
        None => f.render_widget(
            Paragraph::new("No scan running").block(s.block("Progress")),
            prog,
        ),
    }
    if let Some((dir, entries)) = &s.browse {
        let items: Vec<ListItem> = entries.iter().map(|e| ListItem::new(e.as_str())).collect();
        let title = format!("{dir}  (Enter open, s select, Esc close)");
        f.render_stateful_widget(
            List::new(items)
                .block(s.block(&title))
                .highlight_symbol("> "),
            res,
            &mut s.list,
        );
        return;
    }
    let items: Vec<ListItem> = s
        .last_summary
        .as_ref()
        .map(|sm| {
            sm.detections
                .iter()
                .map(|d| ListItem::new(format!("{}: {} ({})", d.path, d.signature, d.action)))
                .collect()
        })
        .unwrap_or_default();
    let title = s
        .last_summary
        .as_ref()
        .map(|sm| {
            format!(
                "Results: {} files, {} threats",
                sm.files,
                sm.detections.len()
            )
        })
        .unwrap_or_else(|| "Results".into());
    f.render_widget(List::new(items).block(s.block(&title)), res);
}

fn protection(f: &mut Frame, s: &State, area: Rect) {
    let Some(st) = &s.status else { return };
    let mut lines = vec![
        Line::from(format!(
            "Real-time: {} ({})",
            if st.realtime.enabled {
                "enabled"
            } else {
                "disabled"
            },
            st.realtime.mode
        )),
        Line::from(format!(
            "Shield: {}  frozen now: {}",
            if st.shield.enabled {
                "enabled"
            } else {
                "disabled"
            },
            st.shield.frozen
        )),
        Line::from(format!("Protected: {}", st.shield.protected.join(", "))),
    ];
    for u in &st.shield.unprotected {
        lines.push(Line::from(Span::styled(
            format!("Unprotected: {u}"),
            Style::default().fg(Color::Yellow),
        )));
    }
    if let Some(set) = &s.settings {
        lines.push(Line::from(format!(
            "Real-time paths: {}",
            set.realtime.include_paths.join(", ")
        )));
        lines.push(Line::from(format!(
            "Exclusions: {}",
            set.scan.exclusions.join(", ")
        )));
        lines.push(Line::from(format!(
            "Shield sensitivity: {:?}",
            set.shield.sensitivity
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from("Recent shield incidents:"));
    for i in s.incidents.iter().take(10) {
        lines.push(Line::from(format!(
            "  {}  {}  {}  {}",
            when(i.time),
            i.state,
            i.app,
            i.exe
        )));
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(s.block("Protection")),
        area,
    );
}

fn quarantine(f: &mut Frame, s: &mut State, area: Rect) {
    let items: Vec<ListItem> = s
        .quarantine
        .iter()
        .map(|q| {
            ListItem::new(format!(
                "{}  {:<10} {:<30} {}",
                when(q.date),
                q.source.as_str(),
                q.signature,
                q.original_path
            ))
        })
        .collect();
    let title = format!("Quarantine ({})", s.quarantine.len());
    f.render_stateful_widget(
        List::new(items)
            .block(s.block(&title))
            .highlight_symbol("> "),
        area,
        &mut s.list,
    );
}

fn network(f: &mut Frame, s: &mut State, area: Rect) {
    let items: Vec<ListItem> = s
        .apps
        .iter()
        .map(|a| {
            ListItem::new(format!(
                "{} {} {:<32} {}",
                if a.blocked { "[BLOCKED]" } else { "[allowed]" },
                if a.allow_lan { "LAN" } else { "   " },
                a.name,
                a.target
            ))
        })
        .collect();
    f.render_stateful_widget(
        List::new(items)
            .block(s.block("Apps"))
            .highlight_symbol("> "),
        area,
        &mut s.list,
    );
}

fn tools(f: &mut Frame, s: &State, area: Rect) {
    let lines: Vec<Line> = if s.tool_out.is_empty() {
        vec![Line::from("Pick a tool with its key. Results show here.")]
    } else {
        s.tool_out.iter().map(|l| Line::from(l.as_str())).collect()
    };
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(s.block("Tools")),
        area,
    );
}

fn history(f: &mut Frame, s: &mut State, area: Rect) {
    let items: Vec<ListItem> = s
        .history
        .iter()
        .map(|e| ListItem::new(format!("{}  {:<10} {}", when(e.time), e.kind, e.summary)))
        .collect();
    f.render_stateful_widget(
        List::new(items)
            .block(s.block("History"))
            .highlight_symbol("> "),
        area,
        &mut s.list,
    );
}

fn settings(f: &mut Frame, s: &State, area: Rect) {
    let Some(r) = &s.reqs else {
        f.render_widget(
            Paragraph::new("Loading...").block(s.block("System requirements")),
            area,
        );
        return;
    };
    let mut rows: Vec<Row> = r
        .rows
        .iter()
        .map(|x| {
            let state = if !x.installed {
                "Missing"
            } else if x.running == Some(false) {
                "Stopped"
            } else {
                "Installed"
            };
            let style = if !x.installed && x.required {
                Style::default().fg(Color::Red)
            } else if !x.installed {
                Style::default().add_modifier(Modifier::DIM)
            } else {
                Style::default()
            };
            Row::new(vec![
                x.tool.clone(),
                if x.required {
                    "Required".into()
                } else {
                    "Optional".into()
                },
                state.into(),
                x.version.clone(),
                x.feature.clone(),
            ])
            .style(style)
        })
        .collect();
    for k in &r.kernel {
        rows.push(Row::new(vec![
            k.name.clone(),
            if k.required {
                "Required".into()
            } else {
                "Optional".into()
            },
            if k.ok { "ok".into() } else { "No".into() },
            String::new(),
            k.detail.clone(),
        ]));
    }
    let title = if r.install_command.is_empty() {
        "System requirements".to_string()
    } else {
        format!("System requirements. Install: {}", r.install_command)
    };
    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(30),
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Length(28),
                Constraint::Min(10),
            ],
        )
        .header(
            Row::new(vec!["Tool", "Needed", "State", "Version", "Used for"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(s.block(&title)),
        area,
    );
}

async fn on_key(c: &Client, s: &mut State, k: KeyEvent) {
    s.msg.clear();
    // Frozen modal first.
    if let Some(inc) = s.frozen.first().cloned() {
        let choice = match k.code {
            KeyCode::Char('K') | KeyCode::Char('k') => "kill",
            KeyCode::Char('A') | KeyCode::Char('a') => "allow-once",
            KeyCode::Char('L') | KeyCode::Char('l') => "allow-always",
            _ => return,
        };
        match c.decide(&inc.id, choice).await {
            Ok(i) => s.msg = format!("{}: {}", i.exe, i.state),
            Err(e) => s.msg = e.to_string(),
        }
        s.frozen = c.frozen().await.unwrap_or_default();
        return;
    }
    if s.input.active {
        match k.code {
            KeyCode::Enter | KeyCode::Esc => s.input.active = false,
            KeyCode::Backspace => {
                s.input.text.pop();
            }
            KeyCode::Char(ch) => s.input.text.push(ch),
            _ => {}
        }
        return;
    }
    if s.help {
        s.help = false;
        return;
    }
    let sel = s.list.selected().unwrap_or(0);
    match k.code {
        KeyCode::Char('q') => s.quit = true,
        KeyCode::Char('?') => s.help = true,
        KeyCode::Tab => switch(s, (s.tab + 1) % TABS.len()),
        KeyCode::BackTab => switch(s, (s.tab + TABS.len() - 1) % TABS.len()),
        KeyCode::Char(ch @ '1'..='8') => switch(s, ch as usize - '1' as usize),
        KeyCode::Down => {
            let n = list_len(s);
            if n > 0 {
                s.list.select(Some((sel + 1).min(n - 1)));
            }
        }
        KeyCode::Up => s.list.select(Some(sel.saturating_sub(1))),
        _ => tab_key(c, s, k, sel).await,
    }
}

fn switch(s: &mut State, tab: usize) {
    s.tab = tab;
    s.list = ListState::default();
    s.list.select(Some(0));
    s.browse = None;
}

async fn start(c: &Client, s: &mut State, paths: Vec<String>, profile: &str) {
    match c.scan(&paths, profile, "manual").await {
        Ok(j) => {
            s.job = Some(j);
            s.last_summary = None;
            s.msg = "Scan started".into();
        }
        Err(e) => s.msg = e.to_string(),
    }
}

async fn tab_key(c: &Client, s: &mut State, k: KeyEvent, sel: usize) {
    let r: Result<String, deadbolt_client::ClientError> = match (s.tab, k.code) {
        (0, KeyCode::Char('s')) => {
            start(c, s, vec![], "quick").await;
            return;
        }
        (0, KeyCode::Char('u')) => c.update_signatures().await,
        (0, KeyCode::Char('p')) => c
            .pause(60)
            .await
            .map(|_| "Protection paused for 1 hour".into()),
        (0, KeyCode::Char('r')) => c.resume().await.map(|_| "Protection resumed".into()),
        (1, KeyCode::Char('e')) => {
            s.input.active = true;
            return;
        }
        (1, KeyCode::Char('b')) => {
            let dir = if s.input.text.starts_with('/') {
                s.input.text.clone()
            } else {
                "/".into()
            };
            let dir = if std::path::Path::new(&dir).is_dir() {
                dir
            } else {
                "/".into()
            };
            s.browse = Some((dir.clone(), read_dir(&dir)));
            s.list.select(Some(0));
            return;
        }
        (1, KeyCode::Esc) => {
            s.browse = None;
            return;
        }
        (1, KeyCode::Enter) if s.browse.is_some() => {
            if let Some((dir, entries)) = s.browse.clone()
                && let Some(e) = entries.get(sel)
            {
                let next = if e == "../" {
                    std::path::Path::new(&dir)
                        .parent()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or(dir)
                } else if let Some(d) = e.strip_suffix('/') {
                    std::path::Path::new(&dir)
                        .join(d)
                        .to_string_lossy()
                        .into_owned()
                } else {
                    s.input.text = std::path::Path::new(&dir)
                        .join(e)
                        .to_string_lossy()
                        .into_owned();
                    s.browse = None;
                    return;
                };
                s.browse = Some((next.clone(), read_dir(&next)));
                s.list.select(Some(0));
            }
            return;
        }
        (1, KeyCode::Char('s')) if s.browse.is_some() => {
            if let Some((dir, _)) = s.browse.take() {
                s.input.text = dir;
            }
            return;
        }
        (1, KeyCode::Enter) => {
            if s.input.text.is_empty() {
                s.msg = "Type a path first (e)".into();
                return;
            }
            let p = vec![s.input.text.clone()];
            start(c, s, p, "custom").await;
            return;
        }
        (1, KeyCode::Char(ch @ ('Q' | 'H' | 'F'))) => {
            let p = match ch {
                'Q' => "quick",
                'H' => "home",
                _ => "full",
            };
            start(c, s, vec![], p).await;
            return;
        }
        (1, KeyCode::Char(' ')) => match (&s.job, &s.progress) {
            (Some(j), Some(p)) => {
                let what = if p.state == JobState::Paused {
                    "resume"
                } else {
                    "pause"
                };
                c.scan_control(j, what)
                    .await
                    .map(|_| format!("Scan {what}d"))
            }
            _ => return,
        },
        (1, KeyCode::Char('c')) => match &s.job {
            Some(j) => c
                .scan_control(j, "cancel")
                .await
                .map(|_| "Cancelling".into()),
            None => return,
        },
        (2, KeyCode::Char(ch @ ('t' | 'g'))) => match c.settings().await {
            Ok(mut set) => {
                if ch == 't' {
                    set.realtime.enabled = !set.realtime.enabled;
                } else {
                    set.shield.enabled = !set.shield.enabled;
                }
                c.set_settings(&set).await.map(|_| "Saved".into())
            }
            Err(e) => Err(e),
        },
        (3, KeyCode::Char('r')) => match s.quarantine.get(sel) {
            Some(q) => c
                .quarantine_restore(&q.id, "", false, false)
                .await
                .map(|p| format!("Restored to {p}")),
            None => return,
        },
        (3, KeyCode::Char('x')) => match s.quarantine.get(sel) {
            Some(q) => c.quarantine_delete(&q.id).await.map(|_| "Deleted".into()),
            None => return,
        },
        (4, KeyCode::Char(ch @ ('b' | 'l'))) => match s.apps.get(sel).cloned() {
            Some(a) => {
                let (blocked, lan) = if ch == 'b' {
                    (!a.blocked, a.allow_lan)
                } else {
                    (true, !a.allow_lan)
                };
                c.net_set(&a.name, &a.kind, &a.target, blocked, lan)
                    .await
                    .map(|_| {
                        format!(
                            "{}: {}",
                            a.name,
                            if blocked { "blocked" } else { "allowed" }
                        )
                    })
            }
            None => return,
        },
        (5, KeyCode::Char(ch @ ('k' | 'c' | 'l' | 'i'))) => {
            let tool = match ch {
                'k' => "rkhunter",
                'c' => "chkrootkit",
                'l' => "lynis",
                _ => {
                    if std::path::Path::new("/usr/bin/debsums").exists() {
                        "debsums"
                    } else {
                        "rpm-verify"
                    }
                }
            };
            s.tool_out = vec![format!("Running {tool}, this can take a few minutes...")];
            c.run_tool(tool).await.map(|_| format!("{tool} started"))
        }
        (5, KeyCode::Char(ch @ ('e' | 'w'))) => {
            let sub = if ch == 'e' { "eicar" } else { "shield" };
            let out = tokio::process::Command::new("deadboltctl")
                .args(["test", sub])
                .output()
                .await;
            match out {
                Ok(o) => {
                    s.tool_out = String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .chain(String::from_utf8_lossy(&o.stderr).lines())
                        .map(String::from)
                        .collect();
                    Ok(format!("{sub} test finished"))
                }
                Err(e) => Ok(format!("cannot run deadboltctl: {e}")),
            }
        }
        (7, KeyCode::Char('d')) => c.requirements(true).await.map(|r| {
            s.reqs = Some(r);
            "Re-checked".into()
        }),
        _ => return,
    };
    s.msg = match r {
        Ok(m) => m,
        Err(e) => e.to_string(),
    };
    refresh(c, s).await;
}

fn on_signal(s: &mut State, sig: Signal) -> bool {
    match sig.member.as_str() {
        "Progress" => {
            if let Ok(p) = serde_json::from_str::<ScanProgress>(&sig.json)
                && Some(&p.job) == s.job.as_ref()
            {
                s.progress = Some(p);
            }
            false
        }
        "Finished" => {
            if let Ok(sm) = serde_json::from_str::<ScanSummary>(&sig.json)
                && Some(&sm.job) == s.job.as_ref()
            {
                s.last_summary = Some(sm);
            }
            true
        }
        "ToolFinished" => {
            let v: Value = serde_json::from_str(&sig.json).unwrap_or_default();
            let r = &v["result"];
            s.tool_out = vec![format!(
                "{}: {}",
                r["tool"].as_str().unwrap_or(""),
                r["summary"].as_str().unwrap_or("")
            )];
            s.tool_out.extend(
                r["findings"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|f| format!("  {}", f.as_str().unwrap_or(""))),
            );
            false
        }
        _ => true,
    }
}

async fn run(mut term: DefaultTerminal, ascii: bool) {
    let mut s = State {
        ascii,
        ..Default::default()
    };
    s.list.select(Some(0));
    let c = match Client::connect().await {
        Ok(c) => c,
        Err(e) => {
            ratatui::restore();
            eprintln!("deadbolt-tui: {e}");
            std::process::exit(2);
        }
    };
    let mut sigs = c.signals().await.ok();
    let (ktx, mut krx) = tokio::sync::mpsc::channel::<KeyEvent>(64);
    std::thread::spawn(move || {
        loop {
            if let Ok(true) = event::poll(Duration::from_millis(200))
                && let Ok(Event::Key(k)) = event::read()
                && k.kind == KeyEventKind::Press
                && ktx.blocking_send(k).is_err()
            {
                break;
            }
        }
    });
    refresh(&c, &mut s).await;
    let mut last = Instant::now();
    while !s.quit {
        let _ = term.draw(|f| draw(f, &mut s));
        tokio::select! {
            Some(k) = krx.recv() => {
                if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
                    break;
                }
                on_key(&c, &mut s, k).await;
            }
            Some(sig) = async { match sigs.as_mut() { Some(r) => r.recv().await, None => std::future::pending().await } } => {
                if on_signal(&mut s, sig) {
                    refresh(&c, &mut s).await;
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
        }
        if last.elapsed() > Duration::from_secs(10) {
            refresh(&c, &mut s).await;
            last = Instant::now();
        }
    }
}

#[tokio::main]
async fn main() {
    let ascii = std::env::args().any(|a| a == "--ascii");
    if std::env::args().any(|a| a == "--version") {
        println!("deadbolt-tui {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let term = ratatui::init();
    run(term, ascii).await;
    ratatui::restore();
}
