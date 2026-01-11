use clap::{Parser, ValueEnum};
use colored::Colorize;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use inquire::MultiSelect;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState},
};
use std::collections::HashSet;
use std::fmt;
use std::io::stdout;
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::System;
use terminal_size::{terminal_size, Width};

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
enum SortBy {
    Cpu,
    Mem,
    Pid,
    Name,
}

#[derive(Parser)]
#[command(name = "rip", version, about = "Fuzzy find and kill processes", disable_version_flag = true)]
struct Args {
    /// Print version
    #[arg(short = 'v', long = "version", action = clap::ArgAction::Version)]
    _version: (),

    /// Pre-filter processes by name
    #[arg(short, long)]
    filter: Option<String>,

    /// Signal to send (default: SIGKILL)
    #[arg(short, long, default_value = "KILL")]
    signal: String,

    /// Sort processes by field (default: cpu)
    #[arg(long, value_enum, default_value = "cpu")]
    sort: SortBy,

    /// Live mode with auto-refreshing process list
    #[arg(short, long)]
    live: bool,
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Calculate available width for the name column based on terminal size
fn calculate_name_width() -> usize {
    let term_width = terminal_size()
        .map(|(Width(w), _)| w as usize)
        .unwrap_or(80);

    // Fixed columns: checkbox(6) + PID(7) + CPU(7) + Memory(9) + spaces(4)
    let fixed = 6 + 7 + 7 + 9 + 4;
    let available = term_width.saturating_sub(fixed);
    available.clamp(20, 80)
}

#[derive(Clone)]
struct ProcessInfo {
    pid: u32,
    name: String,
    cpu: f32,
    memory: u64,
    name_width: usize,
}

impl fmt::Display for ProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let display_name = truncate(&self.name, self.name_width);

        // Format plain strings first with proper widths
        let pid_formatted = format!("{:<7}", self.pid);
        let name_formatted = format!("{:<width$}", display_name, width = self.name_width);
        let cpu_formatted = format!("{:>6.1}%", self.cpu);
        let mem_formatted = format!("{:>9}", format!("{} MB", self.memory));

        // Then apply colors
        let pid_str = Colorize::dimmed(pid_formatted.as_str());
        let name_str = Colorize::white(name_formatted.as_str());
        let cpu_colored = if self.cpu > 50.0 {
            Colorize::bold(Colorize::red(cpu_formatted.as_str()))
        } else if self.cpu > 10.0 {
            Colorize::yellow(cpu_formatted.as_str())
        } else {
            Colorize::dimmed(cpu_formatted.as_str())
        };
        let mem_str = Colorize::cyan(mem_formatted.as_str());

        write!(f, "{} {} {} {}", pid_str, name_str, cpu_colored, mem_str)
    }
}

fn get_processes(filter: Option<&str>, sort_by: SortBy) -> Vec<ProcessInfo> {
    let mut sys = System::new_all();
    sys.refresh_all();
    // Need two samples to get accurate CPU usage
    thread::sleep(Duration::from_millis(200));
    sys.refresh_all();

    let name_width = calculate_name_width();

    let mut processes: Vec<ProcessInfo> = sys
        .processes()
        .iter()
        .filter_map(|(pid, proc)| {
            let name = proc.name().to_string_lossy().to_string();

            // Apply filter if provided
            if let Some(f) = filter {
                if !name.to_lowercase().contains(&f.to_lowercase()) {
                    return None;
                }
            }

            Some(ProcessInfo {
                pid: pid.as_u32(),
                name,
                cpu: proc.cpu_usage(),
                memory: proc.memory() / 1024 / 1024,
                name_width,
            })
        })
        .collect();

    // Sort by selected field
    match sort_by {
        SortBy::Cpu => processes.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap()),
        SortBy::Mem => processes.sort_by(|a, b| b.memory.cmp(&a.memory)),
        SortBy::Pid => processes.sort_by(|a, b| a.pid.cmp(&b.pid)),
        SortBy::Name => processes.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
    }

    processes
}

fn parse_signal(signal_str: &str) -> Result<Signal, String> {
    let signal_str = signal_str.to_uppercase();
    let signal_str = signal_str.strip_prefix("SIG").unwrap_or(&signal_str);

    match signal_str {
        "KILL" | "9" => Ok(Signal::SIGKILL),
        "TERM" | "15" => Ok(Signal::SIGTERM),
        "INT" | "2" => Ok(Signal::SIGINT),
        "HUP" | "1" => Ok(Signal::SIGHUP),
        "QUIT" | "3" => Ok(Signal::SIGQUIT),
        "USR1" | "10" => Ok(Signal::SIGUSR1),
        "USR2" | "12" => Ok(Signal::SIGUSR2),
        "STOP" | "19" => Ok(Signal::SIGSTOP),
        "CONT" | "18" => Ok(Signal::SIGCONT),
        _ => Err(format!("Unknown signal: {}", signal_str)),
    }
}

fn run_selector(processes: Vec<ProcessInfo>) -> Vec<ProcessInfo> {
    if processes.is_empty() {
        return vec![];
    }

    let name_width = calculate_name_width();
    // 4 spaces + "? " from inquire = 6 chars to match checkbox prefix ("> [ ]" or "  [ ]")
    // Format plain strings first, then apply colors
    let pid_h = format!("{:<7}", "PID");
    let name_h = format!("{:<width$}", "NAME", width = name_width);
    let cpu_h = format!("{:>7}", "CPU %");
    let mem_h = format!("{:>9}", "MEMORY");
    let header = format!(
        "    {} {} {} {}",
        Colorize::dimmed(pid_h.as_str()),
        Colorize::dimmed(name_h.as_str()),
        Colorize::dimmed(cpu_h.as_str()),
        Colorize::dimmed(mem_h.as_str()),
    );

    let ans = MultiSelect::new(&format!("{}\n", header), processes)
        .with_page_size(15)
        .with_help_message("↑↓ navigate • Space select • Enter confirm • Type to filter")
        .prompt();

    match ans {
        Ok(selected) => selected,
        Err(_) => vec![],
    }
}

fn run_live_mode(filter: Option<&str>, sort_by: SortBy, signal: Signal) -> std::io::Result<()> {
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

    let mut table_state = TableState::default();
    table_state.select(Some(0));
    let mut selected_pids: HashSet<u32> = HashSet::new();
    let mut last_refresh = Instant::now();
    let refresh_interval = Duration::from_secs(2);
    let mut sys = System::new_all();
    let mut processes = refresh_processes(&mut sys, filter, sort_by);
    let mut show_confirm = false;

    loop {
        // Auto-refresh
        if last_refresh.elapsed() >= refresh_interval && !show_confirm {
            processes = refresh_processes(&mut sys, filter, sort_by);
            last_refresh = Instant::now();
            // Ensure selection is valid
            if let Some(selected) = table_state.selected() {
                if selected >= processes.len() && !processes.is_empty() {
                    table_state.select(Some(processes.len() - 1));
                }
            }
        }

        terminal.draw(|frame| {
            let area = frame.area();

            // Create table rows
            let rows: Vec<Row> = processes
                .iter()
                .map(|p| {
                    let is_selected = selected_pids.contains(&p.pid);
                    let marker = if is_selected { "●" } else { " " };
                    let cpu_style = if p.cpu > 50.0 {
                        Style::default().fg(Color::Red).bold()
                    } else if p.cpu > 10.0 {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    };

                    Row::new(vec![
                        Cell::from(marker).style(if is_selected {
                            Style::default().fg(Color::Green).bold()
                        } else {
                            Style::default()
                        }),
                        Cell::from(format!("{:<7}", p.pid)).style(Style::default().fg(Color::DarkGray)),
                        Cell::from(truncate(&p.name, 40)).style(Style::default().fg(Color::White)),
                        Cell::from(format!("{:>6.1}%", p.cpu)).style(cpu_style),
                        Cell::from(format!("{:>6} MB", p.memory)).style(Style::default().fg(Color::Cyan)),
                    ])
                })
                .collect();

            let header = Row::new(vec![
                Cell::from(" "),
                Cell::from(format!("{:<7}", "PID")).style(Style::default().fg(Color::DarkGray)),
                Cell::from("NAME").style(Style::default().fg(Color::DarkGray)),
                Cell::from(format!("{:>7}", "CPU %")).style(Style::default().fg(Color::DarkGray)),
                Cell::from(format!("{:>9}", "MEMORY")).style(Style::default().fg(Color::DarkGray)),
            ])
            .style(Style::default().bold());

            let widths = [
                Constraint::Length(2),
                Constraint::Length(7),
                Constraint::Min(20),
                Constraint::Length(7),
                Constraint::Length(9),
            ];

            let selected_count = selected_pids.len();
            let title = if selected_count > 0 {
                format!(" rip - {} selected ", selected_count)
            } else {
                " rip ".to_string()
            };

            let table = Table::new(rows, widths)
                .header(header)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(title)
                        .title_bottom(" ↑↓ navigate • Space select • Enter kill • q quit "),
                )
                .row_highlight_style(Style::default().bg(Color::DarkGray).fg(Color::White))
                .highlight_symbol("▶ ");

            frame.render_stateful_widget(table, area, &mut table_state);

            // Show confirmation dialog
            if show_confirm {
                let popup_area = centered_rect(50, 20, area);
                frame.render_widget(Clear, popup_area);

                let count = selected_pids.len();
                let text = format!(
                    "Kill {} process{}?\n\n[Enter] Confirm  [Esc] Cancel",
                    count,
                    if count == 1 { "" } else { "es" }
                );
                let popup = Paragraph::new(text)
                    .alignment(Alignment::Center)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" Confirm ")
                            .border_style(Style::default().fg(Color::Yellow)),
                    );
                frame.render_widget(popup, popup_area);
            }
        })?;

        // Handle input with timeout for refresh
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if show_confirm {
                        match key.code {
                            KeyCode::Enter => {
                                // Kill selected processes
                                break;
                            }
                            KeyCode::Esc => {
                                show_confirm = false;
                            }
                            _ => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => {
                                selected_pids.clear();
                                break;
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                if let Some(selected) = table_state.selected() {
                                    if selected > 0 {
                                        table_state.select(Some(selected - 1));
                                    }
                                }
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                if let Some(selected) = table_state.selected() {
                                    if selected < processes.len().saturating_sub(1) {
                                        table_state.select(Some(selected + 1));
                                    }
                                }
                            }
                            KeyCode::Char(' ') => {
                                if let Some(selected) = table_state.selected() {
                                    if let Some(proc) = processes.get(selected) {
                                        if selected_pids.contains(&proc.pid) {
                                            selected_pids.remove(&proc.pid);
                                        } else {
                                            selected_pids.insert(proc.pid);
                                        }
                                    }
                                }
                            }
                            KeyCode::Enter => {
                                if !selected_pids.is_empty() {
                                    show_confirm = true;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    // Cleanup terminal
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    // Kill selected processes
    if !selected_pids.is_empty() {
        let to_kill: Vec<ProcessInfo> = processes
            .into_iter()
            .filter(|p| selected_pids.contains(&p.pid))
            .collect();
        kill_processes(to_kill, signal);
    }

    Ok(())
}

fn refresh_processes(sys: &mut System, filter: Option<&str>, sort_by: SortBy) -> Vec<ProcessInfo> {
    sys.refresh_all();
    thread::sleep(Duration::from_millis(200));
    sys.refresh_all();

    let name_width = calculate_name_width();

    let mut processes: Vec<ProcessInfo> = sys
        .processes()
        .iter()
        .filter_map(|(pid, proc)| {
            let name = proc.name().to_string_lossy().to_string();

            if let Some(f) = filter {
                if !name.to_lowercase().contains(&f.to_lowercase()) {
                    return None;
                }
            }

            Some(ProcessInfo {
                pid: pid.as_u32(),
                name,
                cpu: proc.cpu_usage(),
                memory: proc.memory() / 1024 / 1024,
                name_width,
            })
        })
        .collect();

    match sort_by {
        SortBy::Cpu => processes.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap()),
        SortBy::Mem => processes.sort_by(|a, b| b.memory.cmp(&a.memory)),
        SortBy::Pid => processes.sort_by(|a, b| a.pid.cmp(&b.pid)),
        SortBy::Name => processes.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
    }

    processes
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(r);

    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(popup_layout[1])[1]
}

fn kill_processes(selected: Vec<ProcessInfo>, signal: Signal) {
    for proc in selected {
        match kill(Pid::from_raw(proc.pid as i32), signal) {
            Ok(_) => println!(
                "{} {} {}",
                Colorize::green("Killed"),
                Colorize::bold(proc.name.as_str()),
                Colorize::dimmed(format!("(PID: {})", proc.pid).as_str())
            ),
            Err(e) => eprintln!(
                "{} {} {}: {}",
                Colorize::red("Failed"),
                Colorize::bold(proc.name.as_str()),
                Colorize::dimmed(format!("(PID: {})", proc.pid).as_str()),
                e
            ),
        }
    }
}

fn main() {
    let args = Args::parse();

    let signal = match parse_signal(&args.signal) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    if args.live {
        if let Err(e) = run_live_mode(args.filter.as_deref(), args.sort, signal) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    let processes = get_processes(args.filter.as_deref(), args.sort);

    if processes.is_empty() {
        println!("No processes found");
        return;
    }

    let selected = run_selector(processes);

    if selected.is_empty() {
        println!("No processes selected");
        return;
    }

    kill_processes(selected, signal);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_signal_kill() {
        assert_eq!(parse_signal("KILL").unwrap(), Signal::SIGKILL);
        assert_eq!(parse_signal("kill").unwrap(), Signal::SIGKILL);
        assert_eq!(parse_signal("SIGKILL").unwrap(), Signal::SIGKILL);
        assert_eq!(parse_signal("9").unwrap(), Signal::SIGKILL);
    }

    #[test]
    fn test_parse_signal_term() {
        assert_eq!(parse_signal("TERM").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("term").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("SIGTERM").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("15").unwrap(), Signal::SIGTERM);
    }

    #[test]
    fn test_parse_signal_int() {
        assert_eq!(parse_signal("INT").unwrap(), Signal::SIGINT);
        assert_eq!(parse_signal("2").unwrap(), Signal::SIGINT);
    }

    #[test]
    fn test_parse_signal_hup() {
        assert_eq!(parse_signal("HUP").unwrap(), Signal::SIGHUP);
        assert_eq!(parse_signal("1").unwrap(), Signal::SIGHUP);
    }

    #[test]
    fn test_parse_signal_invalid() {
        assert!(parse_signal("INVALID").is_err());
        assert!(parse_signal("999").is_err());
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("this is a very long string", 10), "this is...");
    }

    #[test]
    fn test_get_processes_returns_non_empty() {
        let processes = get_processes(None, SortBy::Cpu);
        assert!(!processes.is_empty(), "Should return at least one process");
    }

    #[test]
    fn test_get_processes_with_filter() {
        let all_processes = get_processes(None, SortBy::Cpu);
        let filtered = get_processes(Some("NONEXISTENT_PROCESS_12345"), SortBy::Cpu);
        assert!(filtered.len() <= all_processes.len());
    }

    #[test]
    fn test_sort_by_values() {
        let _ = get_processes(None, SortBy::Cpu);
        let _ = get_processes(None, SortBy::Mem);
        let _ = get_processes(None, SortBy::Pid);
        let _ = get_processes(None, SortBy::Name);
    }

    #[test]
    fn test_process_info_display() {
        let proc = ProcessInfo {
            pid: 1234,
            name: "test_process".to_string(),
            cpu: 25.5,
            memory: 512,
            name_width: 35,
        };
        let display = format!("{}", proc);
        assert!(display.contains("1234"));
        assert!(display.contains("test_process"));
    }
}
