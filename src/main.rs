use clap::{Parser, ValueEnum};
use colored::Colorize;
use inquire::MultiSelect;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::fmt;
use std::thread;
use std::time::Duration;
use sysinfo::System;

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
enum SortBy {
    Cpu,
    Mem,
    Pid,
    Name,
}

#[derive(Parser)]
#[command(name = "rip")]
#[command(about = "Fuzzy find and kill processes", long_about = None)]
struct Args {
    /// Pre-filter processes by name
    #[arg(short, long)]
    filter: Option<String>,

    /// Signal to send (default: SIGKILL)
    #[arg(short, long, default_value = "KILL")]
    signal: String,

    /// Sort processes by field (default: cpu)
    #[arg(long, value_enum, default_value = "cpu")]
    sort: SortBy,
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

#[derive(Clone)]
struct ProcessInfo {
    pid: u32,
    name: String,
    cpu: f32,
    memory: u64,
}

impl fmt::Display for ProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let display_name = truncate(&self.name, 35);
        let pid_str = format!("{:<7}", self.pid).dimmed();
        let name_str = format!("{:<35}", display_name).white();
        let cpu_str = format!("{:>5.1}%", self.cpu);
        let cpu_colored = if self.cpu > 50.0 {
            cpu_str.red().bold()
        } else if self.cpu > 10.0 {
            cpu_str.yellow()
        } else {
            cpu_str.dimmed()
        };
        let mem_str = format!("{:>6} MB", self.memory).cyan();

        write!(f, "{} {} {} {}", pid_str, name_str, cpu_colored, mem_str)
    }
}

fn get_processes(filter: Option<&str>, sort_by: SortBy) -> Vec<ProcessInfo> {
    let mut sys = System::new_all();
    sys.refresh_all();
    // Need two samples to get accurate CPU usage
    thread::sleep(Duration::from_millis(200));
    sys.refresh_all();

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

    let header = format!(
        "{:<7} {:<35} {:>6} {:>9}",
        "PID".dimmed(),
        "NAME".dimmed(),
        "CPU %".dimmed(),
        "MEMORY".dimmed()
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

fn kill_processes(selected: Vec<ProcessInfo>, signal: Signal) {
    for proc in selected {
        match kill(Pid::from_raw(proc.pid as i32), signal) {
            Ok(_) => println!(
                "{} {} {}",
                "Killed".green(),
                proc.name.bold(),
                format!("(PID: {})", proc.pid).dimmed()
            ),
            Err(e) => eprintln!(
                "{} {} {}: {}",
                "Failed".red(),
                proc.name.bold(),
                format!("(PID: {})", proc.pid).dimmed(),
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
        };
        let display = format!("{}", proc);
        assert!(display.contains("1234"));
        assert!(display.contains("test_process"));
    }
}
